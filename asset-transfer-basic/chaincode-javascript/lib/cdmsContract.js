// cmdsContract.js
'use strict';

const { Contract } = require('fabric-contract-api');
const { v4: uuidv4 } = require('uuid'); // ensure uuid is in package.json dependencies

class CdmsContract extends Contract {

    constructor() {
        super('org.cdms.cdmscontract');
    }

    // Optional: initialize ledger with sample data
    async InitLedger(ctx) {
        console.info('=== Init Ledger ===');
        const samples = [];

        for (const r of samples) {
            const key = ctx.stub.createCompositeKey('record', [r.record_id]);
            await ctx.stub.putState(key, Buffer.from(JSON.stringify(r)));
            // no audit created here; real flows should call AddAudit on operations
        }
        console.info('=== Ledger initialized ===');
    }

    // -----------------------
    // CreateRecord
    // -----------------------
    /**
     * CreateRecord expects a JSON string/object containing at least:
     * record_id, case_id, record_type, uploader_org, offchain_uri, file_hash, wrapped_key_ref, policy_id
     */
    async CreateRecord(ctx, recordJSON) {
        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['investigator', 'admin'])) {
            throw new Error('CreateRecord: caller not authorized (must be investigator or admin)');
        }

        let record;
        if (typeof recordJSON === 'string') {
            try { record = JSON.parse(recordJSON); } catch (err) { throw new Error('CreateRecord: invalid JSON'); }
        } else {
            record = recordJSON;
        }

        if (!record.record_id) record.record_id = uuidv4();
        if (!record.case_id) throw new Error('CreateRecord: missing case_id');
        if (!record.offchain_uri) throw new Error('CreateRecord: missing offchain_uri');
        if (!record.wrapped_key_ref) throw new Error('CreateRecord: missing wrapped_key_ref');

        const key = ctx.stub.createCompositeKey('record', [record.record_id]);
        const exists = await ctx.stub.getState(key);
        if (exists && exists.length > 0) throw new Error(`CreateRecord: record ${record.record_id} already exists`);

        // enrich
        record.uploader = this._getClientId(ctx);
        record.uploader_org = record.uploader_org || this._getClientAttr(ctx, 'organization') || ctx.clientIdentity.getMSPID();
        record.created_at = new Date().toISOString();
        record.status = record.status || 'active';

        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));

        // create an initial audit entry
        const audit = {
            audit_id: uuidv4(),
            record_id: record.record_id,
            action: 'CreateRecord',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: new Date().toISOString(),
            details: `Record created by ${callerRole}`
        };
        await this._storeAudit(ctx, record.record_id, audit);

        // Emit event
        ctx.stub.setEvent('RecordCreated', Buffer.from(JSON.stringify({ record_id: record.record_id, case_id: record.case_id })));

        return record.record_id;
    }

    // -----------------------
    // ReadRecord
    // -----------------------
    async ReadRecord(ctx, recordId) {
        if (!recordId) throw new Error('ReadRecord: recordId required');

        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['investigator', 'forensics_officer', 'admin'])) {
            throw new Error('ReadRecord: caller not authorized (investigator/forensics_officer/admin only)');
        }

        const key = ctx.stub.createCompositeKey('record', [recordId]);
        const data = await ctx.stub.getState(key);
        if (!data || data.length === 0) throw new Error(`ReadRecord: record ${recordId} does not exist`);

        // return metadata only; offchain_uri and wrapped_key_ref are included intentionally (business decision)
        // If you want to limit wrapped_key_ref exposure, remove it here or require additional checks.
        const record = JSON.parse(data.toString());

        // write audit for read
        const audit = {
            audit_id: uuidv4(),
            record_id: recordId,
            action: 'ReadRecord',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: new Date().toISOString(),
            details: `Record read by ${callerRole}`
        };
        await this._storeAudit(ctx, recordId, audit);

        return record;
    }

    // -----------------------
    // QueryRecordsByCase
    // -----------------------
    async QueryRecordsByCase(ctx, caseId) {
        if (!caseId) throw new Error('QueryRecordsByCase: caseId required');

        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['investigator', 'forensics_officer', 'admin'])) {
            throw new Error('QueryRecordsByCase: caller not authorized (investigator/forensics_officer/admin only)');
        }

        const iterator = await ctx.stub.getStateByPartialCompositeKey('record', []);
        const results = [];
        while (true) {
            const res = await iterator.next();
            if (res.value && res.value.value.toString()) {
                const record = JSON.parse(res.value.value.toString('utf8'));
                if (record.case_id === caseId) results.push(record);
            }
            if (res.done) {
                await iterator.close();
                break;
            }
        }

        // audit
        const audit = {
            audit_id: uuidv4(),
            record_id: `case:${caseId}`,
            action: 'QueryRecordsByCase',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: new Date().toISOString(),
            details: `Queried records for case ${caseId}`
        };
        await this._storeAudit(ctx, `case-${caseId}`, audit);

        return results;
    }

    // -----------------------
    // AddAudit
    // -----------------------
    async AddAudit(ctx, recordId, action, details) {
        if (!recordId || !action) throw new Error('AddAudit: recordId and action required');

        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['investigator', 'forensics_officer', 'admin'])) {
            throw new Error('AddAudit: caller not authorized (investigator/forensics_officer/admin only)');
        }

        // check record exists (allow adding audit for non-existing? we require existing)
        const recKey = ctx.stub.createCompositeKey('record', [recordId]);
        const rec = await ctx.stub.getState(recKey);
        if (!rec || rec.length === 0) throw new Error(`AddAudit: record ${recordId} does not exist`);

        const audit = {
            audit_id: uuidv4(),
            record_id: recordId,
            action,
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: new Date().toISOString(),
            details: details || ''
        };
        await this._storeAudit(ctx, recordId, audit);

        // emit event
        ctx.stub.setEvent('AuditAdded', Buffer.from(JSON.stringify({ record_id: recordId, action })));

        return audit.audit_id;
    }

    // -----------------------
    // CreatePolicy
    // -----------------------
    /**
     * policyJSON can be string or object, minimal fields: policy_id, rules (small JSON)
     */
    async CreatePolicy(ctx, policyId, policyJSON) {
        if (!policyId) throw new Error('CreatePolicy: policyId required');

        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['admin'])) {
            throw new Error('CreatePolicy: caller not authorized (admin only)');
        }

        let policy;
        if (typeof policyJSON === 'string') {
            try { policy = JSON.parse(policyJSON); } catch (err) { throw new Error('CreatePolicy: invalid JSON'); }
        } else {
            policy = policyJSON;
        }

        policy.policy_id = policyId;
        policy.created_by = this._getClientId(ctx);
        policy.created_at = new Date().toISOString();

        const key = ctx.stub.createCompositeKey('policy', [policyId]);
        const existing = await ctx.stub.getState(key);
        if (existing && existing.length > 0) {
            throw new Error(`CreatePolicy: policy ${policyId} already exists`);
        }

        await ctx.stub.putState(key, Buffer.from(JSON.stringify(policy)));
        ctx.stub.setEvent('PolicyCreated', Buffer.from(JSON.stringify({ policy_id: policyId })));
        return policyId;
    }

    async GetPolicy(ctx, policyId) {
        if (!policyId) throw new Error('GetPolicy: policyId required');

        // Anyone authenticated can fetch policy (policy are small & non-sensitive). If sensitive, enforce role check.
        const key = ctx.stub.createCompositeKey('policy', [policyId]);
        const data = await ctx.stub.getState(key);
        if (!data || data.length === 0) throw new Error(`GetPolicy: policy ${policyId} does not exist`);
        return JSON.parse(data.toString());
    }

    // -----------------------
    // ListAllRecords
    // -----------------------
    async ListAllRecords(ctx) {
        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['investigator', 'forensics_officer', 'admin'])) {
            throw new Error('ListAllRecords: caller not authorized');
        }

        const iterator = await ctx.stub.getStateByPartialCompositeKey('record', []);
        const results = [];
        while (true) {
            const res = await iterator.next();
            if (res.value && res.value.value.toString()) {
                const record = JSON.parse(res.value.value.toString('utf8'));
                results.push(record);
            }
            if (res.done) {
                await iterator.close();
                break;
            }
        }
        return results;
    }

    // -----------------------
    // Helpers
    // -----------------------
    _getClientId(ctx) {
        try {
            return ctx.clientIdentity.getID();
        } catch (err) {
            return 'unknown';
        }
    }

    _getClientAttr(ctx, attr) {
        try {
            const v = ctx.clientIdentity.getAttributeValue(attr);
            return v || null;
        } catch (err) {
            return null;
        }
    }

    _isAllowed(roleValue, allowedArray) {
        if (!roleValue) return false;
        return allowedArray.includes(roleValue);
    }

    async _storeAudit(ctx, recordId, auditObj) {
        // audit composite key: audit~recordId~timestamp~uuid
        const ts = new Date().toISOString();
        const auditKey = ctx.stub.createCompositeKey('audit', [recordId, ts, auditObj.audit_id || uuidv4()]);
        await ctx.stub.putState(auditKey, Buffer.from(JSON.stringify(auditObj)));
    }

}

module.exports = CdmsContract;
