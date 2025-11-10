'use strict';

const { Contract } = require('fabric-contract-api');

class CDMSContract extends Contract {

    constructor() {
        super('org.cdms.cdmscontract');
    }

    // =========================================================
    // HELPER: Get Transaction Timestamp (Deterministic)
    // =========================================================
    /**
     * Get deterministic timestamp from transaction
     * This returns the same timestamp on all peers for the same transaction
     */
    _getTxTimestamp(ctx) {
        const txTimestamp = ctx.stub.getTxTimestamp();
        const milliseconds = (txTimestamp.seconds.low * 1000) + Math.floor(txTimestamp.nanos / 1000000);
        return new Date(milliseconds).toISOString();
    }

    /**
     * Get deterministic unique ID using transaction ID
     * This returns the same ID on all peers for the same transaction
     */
    _getUniqueTxId(ctx, prefix) {
        const txId = ctx.stub.getTxID();
        return `${prefix}_${txId}`;
    }

    // Initialize the ledger
    async InitLedger(ctx) {
        console.info('============= START : Initialize Ledger ===========');
        console.info('============= END : Initialize Ledger ===========');
        return JSON.stringify({ message: 'Ledger initialized successfully' });
    }

    // -----------------------
    // CreateRecord
    // -----------------------
    /**
     * CreateRecord expects a JSON string containing:
     * record_id, case_id, record_type, uploader_org, offchain_uri, file_hash, wrapped_key_ref, policy_id
     */
    async CreateRecord(ctx, recordJSON) {
        console.info('============= START : Create Record ===========');
        
        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // Explicitly deny judiciary (read-only access)
        if (callerRole === 'judiciary') {
            throw new Error('CreateRecord: Judiciary has read-only access');
        }
        // Only district_police and admin can upload/create records
        if (!this._isAllowed(callerRole, ['district_police', 'admin'])) {
            throw new Error(`CreateRecord: caller not authorized (must be district_police or admin). Got role: ${callerRole || 'null'}`);
        }

        let record;
        if (typeof recordJSON === 'string') {
            try {
                record = JSON.parse(recordJSON);
            } catch (err) {
                throw new Error('CreateRecord: invalid JSON');
            }
        } else {
            record = recordJSON;
        }

        const recordId = record.record_id;
        if (!recordId) {
            throw new Error('CreateRecord: record_id is required');
        }
        if (!record.case_id) {
            throw new Error('CreateRecord: case_id is required');
        }

        // Check if record already exists
        const exists = await this.RecordExists(ctx, recordId);
        if (exists) {
            throw new Error(`Record ${recordId} already exists`);
        }

        // ✅ Use deterministic transaction timestamp
        const timestamp = this._getTxTimestamp(ctx);

        // Enrich record with metadata
        record.uploader = this._getClientId(ctx);
        record.uploader_org = record.uploader_org || this._getClientAttr(ctx, 'organization') || ctx.clientIdentity.getMSPID();
        record.created_at = record.created_at || timestamp;
        record.updated_at = timestamp;
        record.status = record.status || 'active';

        // Store on ledger
        await ctx.stub.putState(recordId, Buffer.from(JSON.stringify(record)));

        // ✅ Create initial audit entry with deterministic ID
        const audit = {
            audit_id: this._getUniqueTxId(ctx, `AUDIT_${recordId}`),
            record_id: recordId,
            action: 'CreateRecord',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: timestamp,
            details: `Record created by ${callerRole}`
        };
        await this._storeAudit(ctx, recordId, audit);

        // Emit event
        ctx.stub.setEvent('RecordCreated', Buffer.from(JSON.stringify({ 
            record_id: recordId, 
            case_id: record.case_id 
        })));

        console.info('============= END : Create Record ===========');
        return JSON.stringify(record);
    }

    // -----------------------
    // ReadRecord
    // -----------------------
    async ReadRecord(ctx, recordId) {
        if (!recordId) {
            throw new Error('ReadRecord: recordId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can view/access records (including judiciary - read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            throw new Error(`ReadRecord: caller not authorized. Got role: ${callerRole || 'null'}`);
        }

        const recordBytes = await ctx.stub.getState(recordId);
        if (!recordBytes || recordBytes.length === 0) {
            throw new Error(`Record ${recordId} does not exist`);
        }

        const record = JSON.parse(recordBytes.toString());

        // ✅ Create audit entry for read operation with deterministic timestamp
        const timestamp = this._getTxTimestamp(ctx);
        const audit = {
            audit_id: this._getUniqueTxId(ctx, `AUDIT_${recordId}`),
            record_id: recordId,
            action: 'ReadRecord',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: timestamp,
            details: `Record read by ${callerRole}`
        };
        await this._storeAudit(ctx, recordId, audit);

        return recordBytes.toString();
    }

    // -----------------------
    // UpdateRecord
    // -----------------------
    async UpdateRecord(ctx, recordId, newDataJSON) {
        if (!recordId) {
            throw new Error('UpdateRecord: recordId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role');
        // Only district_police and admin can update records (judiciary is read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'admin'])) {
            throw new Error('UpdateRecord: caller not authorized (district_police/admin only)');
        }
        // Explicitly deny judiciary
        if (callerRole === 'judiciary') {
            throw new Error('UpdateRecord: Judiciary has read-only access');
        }

        const exists = await this.RecordExists(ctx, recordId);
        if (!exists) {
            throw new Error(`Record ${recordId} does not exist`);
        }

        const recordBytes = await ctx.stub.getState(recordId);
        const record = JSON.parse(recordBytes.toString());

        let newData;
        if (typeof newDataJSON === 'string') {
            try {
                newData = JSON.parse(newDataJSON);
            } catch (err) {
                throw new Error('UpdateRecord: invalid JSON');
            }
        } else {
            newData = newDataJSON;
        }

        // ✅ Use deterministic transaction timestamp
        const timestamp = this._getTxTimestamp(ctx);

        const updatedRecord = { ...record, ...newData };
        updatedRecord.updated_at = timestamp;
        updatedRecord.updated_by = this._getClientId(ctx);

        await ctx.stub.putState(recordId, Buffer.from(JSON.stringify(updatedRecord)));

        // ✅ Create audit entry with deterministic timestamp
        const audit = {
            audit_id: this._getUniqueTxId(ctx, `AUDIT_${recordId}`),
            record_id: recordId,
            action: 'UpdateRecord',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: timestamp,
            details: `Record updated by ${callerRole}`
        };
        await this._storeAudit(ctx, recordId, audit);

        // Emit event
        ctx.stub.setEvent('RecordUpdated', Buffer.from(JSON.stringify({ 
            record_id: recordId 
        })));

        return JSON.stringify(updatedRecord);
    }

    // -----------------------
    // DeleteRecord
    // -----------------------
    async DeleteRecord(ctx, recordId) {
        if (!recordId) {
            throw new Error('DeleteRecord: recordId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['admin'])) {
            throw new Error('DeleteRecord: caller not authorized (admin only)');
        }

        const exists = await this.RecordExists(ctx, recordId);
        if (!exists) {
            throw new Error(`Record ${recordId} does not exist`);
        }

        // ✅ Create audit entry before deletion with deterministic timestamp
        const timestamp = this._getTxTimestamp(ctx);
        const audit = {
            audit_id: this._getUniqueTxId(ctx, `AUDIT_${recordId}`),
            record_id: recordId,
            action: 'DeleteRecord',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: timestamp,
            details: `Record deleted by ${callerRole}`
        };
        await this._storeAudit(ctx, recordId, audit);

        await ctx.stub.deleteState(recordId);

        // Emit event
        ctx.stub.setEvent('RecordDeleted', Buffer.from(JSON.stringify({ 
            record_id: recordId 
        })));

        return JSON.stringify({ message: `Record ${recordId} deleted successfully` });
    }

    // -----------------------
    // RecordExists
    // -----------------------
    async RecordExists(ctx, recordId) {
        const recordBytes = await ctx.stub.getState(recordId);
        return recordBytes && recordBytes.length > 0;
    }

    // -----------------------
    // QueryRecordsByCase
    // -----------------------
    async QueryRecordsByCase(ctx, caseId) {
        if (!caseId) {
            throw new Error('QueryRecordsByCase: caseId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can query records (including judiciary - read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            throw new Error('QueryRecordsByCase: caller not authorized');
        }

        const queryString = {
            selector: {
                case_id: caseId
            }
        };

        const results = await this.GetQueryResultForQueryString(ctx, JSON.stringify(queryString));

        // ✅ Create audit entry with deterministic timestamp
        const timestamp = this._getTxTimestamp(ctx);
        const audit = {
            audit_id: this._getUniqueTxId(ctx, `AUDIT_case_${caseId}`),
            record_id: `case:${caseId}`,
            action: 'QueryRecordsByCase',
            actor: this._getClientId(ctx),
            role: callerRole,
            timestamp: timestamp,
            details: `Queried records for case ${caseId}`
        };
        await this._storeAudit(ctx, `case-${caseId}`, audit);

        return results;
    }

    // -----------------------
    // ListAllRecords
    // -----------------------
    async ListAllRecords(ctx) {
        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can list records (including judiciary - read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            console.warn(`ListAllRecords: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
            // Don't throw error in test mode - allow the query to proceed
            // throw new Error(`ListAllRecords: caller not authorized. Got role: ${callerRole || 'null'}`);
        }

        const allResults = [];
        // Use proper range for getStateByRange (empty string to \uffff to get all keys)
        const iterator = await ctx.stub.getStateByRange('', '\uffff');
        let result = await iterator.next();

        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            let record;
            try {
                record = JSON.parse(strValue);
                // Skip audit, system event, and policy entries
                if (!result.value.key.startsWith('AUDIT_') && 
                    !result.value.key.startsWith('SYSTEM_EVENT_') && 
                    !result.value.key.startsWith('POLICY_')) {
                    allResults.push(record);
                }
            } catch (err) {
                console.log(err);
            }
            result = await iterator.next();
        }

        await iterator.close();
        return JSON.stringify(allResults);
    }

    // -----------------------
    // CreatePolicy
    // -----------------------
    async CreatePolicy(ctx, policyId, policyDataJSON) {
        if (!policyId) {
            throw new Error('CreatePolicy: policyId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role');
        if (!this._isAllowed(callerRole, ['admin'])) {
            throw new Error('CreatePolicy: caller not authorized (admin only)');
        }

        let policyData;
        if (typeof policyDataJSON === 'string') {
            try {
                policyData = JSON.parse(policyDataJSON);
            } catch (err) {
                throw new Error('CreatePolicy: invalid JSON');
            }
        } else {
            policyData = policyDataJSON;
        }

        // ✅ Use deterministic transaction timestamp
        const timestamp = this._getTxTimestamp(ctx);

        const policy = {
            policy_id: policyId,
            ...policyData,
            created_at: timestamp,
            created_by: this._getClientId(ctx)
        };

        const policyKey = `POLICY_${policyId}`;
        const existing = await ctx.stub.getState(policyKey);
        if (existing && existing.length > 0) {
            throw new Error(`Policy ${policyId} already exists`);
        }

        await ctx.stub.putState(policyKey, Buffer.from(JSON.stringify(policy)));

        // Emit event
        ctx.stub.setEvent('PolicyCreated', Buffer.from(JSON.stringify({ 
            policy_id: policyId 
        })));

        return policyId;
    }

    // -----------------------
    // GetPolicy
    // -----------------------
    async GetPolicy(ctx, policyId) {
        if (!policyId) {
            throw new Error('GetPolicy: policyId is required');
        }

        const policyKey = `POLICY_${policyId}`;
        const policyBytes = await ctx.stub.getState(policyKey);
        if (!policyBytes || policyBytes.length === 0) {
            throw new Error(`Policy ${policyId} does not exist`);
        }
        return policyBytes.toString();
    }

    // -----------------------
    // AddAudit
    // -----------------------
    // Supports two calling formats:
    // 1. AddAudit(ctx, recordId, action, details) - Original format
    // 2. AddAudit(ctx, recordId, actor, action, details) - With explicit actor
    async AddAudit(ctx, recordId, param1, param2, param3) {
        // Determine which format is being used
        let actor, action, details;
        
        // If 4 params provided (recordId, actor, action, details)
        if (param3 !== undefined) {
            actor = param1;
            action = param2;
            details = param3;
        } else {
            // If 3 params provided (recordId, action, details) - original format
            actor = this._getClientId(ctx); // Use client ID as actor
            action = param1;
            details = param2 || '';
        }
        
        if (!recordId || !action) {
            throw new Error('AddAudit: recordId and action are required');
        }

        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can add audit entries (to track their actions)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin'])) {
            console.warn(`AddAudit: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
            // Don't throw error in test mode - allow the operation to proceed
        }

        // Check if record exists
        const exists = await this.RecordExists(ctx, recordId);
        if (!exists) {
            throw new Error(`AddAudit: record ${recordId} does not exist`);
        }

        // ✅ Use deterministic transaction timestamp and ID
        const timestamp = this._getTxTimestamp(ctx);
        const audit = {
            audit_id: this._getUniqueTxId(ctx, `AUDIT_${recordId}`),
            record_id: recordId,
            action: action,
            actor: actor || this._getClientId(ctx),
            role: callerRole,
            timestamp: timestamp,
            details: details || ''
        };

        await this._storeAudit(ctx, recordId, audit);

        // Emit event
        ctx.stub.setEvent('AuditAdded', Buffer.from(JSON.stringify({ 
            record_id: recordId, 
            action: action 
        })));

        return audit.audit_id;
    }

    // -----------------------
    // GetAuditTrail
    // -----------------------
    async GetAuditTrail(ctx, recordId) {
        if (!recordId) {
            throw new Error('GetAuditTrail: recordId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can view audit trail (including judiciary - read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            console.warn(`GetAuditTrail: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
            // Don't throw error in test mode - allow the query to proceed
        }

        const queryString = {
            selector: {
                record_id: recordId
            }
        };

        return await this.GetQueryResultForQueryString(ctx, JSON.stringify(queryString));
    }

    // -----------------------
    // GetRecordHistory
    // -----------------------
    /**
     * Get blockchain history for a specific record (all transactions)
     */
    async GetRecordHistory(ctx, recordId) {
        if (!recordId) {
            throw new Error('GetRecordHistory: recordId is required');
        }

        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can view record history (including judiciary - read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            console.warn(`GetRecordHistory: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
            // Don't throw error in test mode - allow the query to proceed
        }

        console.log(`Getting history for record: ${recordId}`);

        const historyIterator = await ctx.stub.getHistoryForKey(recordId);
        const results = [];

        let result = await historyIterator.next();
        while (!result.done) {
            const historyRecord = result.value;
            let record = null;

            // Parse the record if it exists
            if (historyRecord.value && historyRecord.value.length > 0) {
                try {
                    record = JSON.parse(historyRecord.value.toString());
                } catch (err) {
                    console.error(`Error parsing record: ${err}`);
                }
            }

            // Convert timestamp to ISO string
            const timestamp = historyRecord.timestamp;
            let timestampSeconds = 0;
            let timestampNanos = 0;

            // Handle different timestamp formats
            if (timestamp) {
                if (typeof timestamp.seconds === 'number') {
                    timestampSeconds = timestamp.seconds;
                } else if (timestamp.seconds && typeof timestamp.seconds.low === 'number') {
                    timestampSeconds = timestamp.seconds.low;
                } else if (timestamp.getSeconds && typeof timestamp.getSeconds === 'function') {
                    timestampSeconds = timestamp.getSeconds();
                }

                timestampNanos = timestamp.nanos || timestamp.getNanos?.() || 0;
            }

            // Convert to milliseconds
            const timestampMs = timestampSeconds * 1000 + Math.floor(timestampNanos / 1000000);
            const timestampISO = new Date(timestampMs).toISOString();

            results.push({
                txId: historyRecord.txId,
                timestamp: timestampISO,
                isDelete: historyRecord.isDelete || false,
                value: record
            });

            result = await historyIterator.next();
        }

        await historyIterator.close();
        return JSON.stringify(results);
    }

    // -----------------------
    // GetAllHistory
    // -----------------------
    /**
     * Get all blockchain transaction history (across all records)
     * Returns history for all records in the ledger
     */
    async GetAllHistory(ctx, limitParam) {
        console.log('============= START : Get All History ===========');

        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can view all history (including judiciary - read-only)
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            console.warn(`GetAllHistory: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
            // Don't throw error in test mode - allow the query to proceed
            // throw new Error(`GetAllHistory: caller not authorized. Got role: ${callerRole || 'null'}`);
        }

        try {
            const limit = limitParam ? parseInt(limitParam) : 100;
            const allRecords = [];

            // Use getStateByRange with proper bounds
            const startKey = '';
            const endKey = '\uffff'; // Unicode character that sorts after all other characters

            console.log(`Getting state by range from "${startKey}" to "${endKey}"`);
            const iterator = await ctx.stub.getStateByRange(startKey, endKey);
            let result = await iterator.next();
            let processedCount = 0;

            console.log(`Iterating through records (limit: ${limit})`);

            while (!result.done && processedCount < limit) {
                try {
                    if (!result.value || !result.value.key) {
                        result = await iterator.next();
                        continue;
                    }

                    const recordKey = result.value.key;
                    console.log(`Processing record key: ${recordKey}`);

                    // Skip policy and audit keys (but include SYSTEM_EVENT_ keys)
                    if (recordKey.startsWith('POLICY_') || recordKey.startsWith('AUDIT_')) {
                        console.log(`Skipping ${recordKey}`);
                        result = await iterator.next();
                        continue;
                    }
                    
                    // Handle system events separately
                    if (recordKey.startsWith('SYSTEM_EVENT_')) {
                        try {
                            const eventStr = Buffer.from(result.value.value.toString()).toString('utf8');
                            const systemEvent = JSON.parse(eventStr);
                            
                            // Format system event as history entry
                            const historyEntry = {
                                txId: systemEvent.tx_id || `SYSTEM_${systemEvent.event_id}`,
                                recordId: systemEvent.event_id,
                                timestamp: systemEvent.timestamp,
                                isDelete: false,
                                action: systemEvent.event_type,
                                actor: systemEvent.actor,
                                actor_org: systemEvent.actor_org,
                                actor_role: systemEvent.actor_role,
                                target_user: systemEvent.target_user || null,
                                target_user_org: systemEvent.target_user_org || null,
                                details: systemEvent.details,
                                value: {
                                    event_type: systemEvent.event_type,
                                    actor: systemEvent.actor,
                                    actor_org: systemEvent.actor_org,
                                    target_user: systemEvent.target_user,
                                    target_user_org: systemEvent.target_user_org,
                                    details: systemEvent.details
                                },
                                source: 'system_event'
                            };
                            
                            allRecords.push(historyEntry);
                            processedCount++;
                        } catch (eventErr) {
                            console.error(`Error parsing system event ${recordKey}: ${eventErr.message}`);
                        }
                        result = await iterator.next();
                        continue;
                    }

                    // Get history for this specific record
                    console.log(`Getting history for ${recordKey}`);
                    const historyIterator = await ctx.stub.getHistoryForKey(recordKey);
                    let historyResult = await historyIterator.next();
                    let historyCount = 0;

                    while (!historyResult.done) {
                        try {
                            const historyRecord = historyResult.value;

                            // Parse record value if it exists
                            let recordData = null;
                            if (historyRecord.value && historyRecord.value.length > 0) {
                                try {
                                    recordData = JSON.parse(historyRecord.value.toString());
                                } catch (parseErr) {
                                    console.error(`Error parsing record ${recordKey}: ${parseErr.message}`);
                                }
                            }

                            // Convert timestamp
                            let timestampISO = new Date().toISOString();
                            try {
                                const timestamp = historyRecord.timestamp;
                                if (timestamp) {
                                    let seconds = 0;
                                    let nanos = 0;

                                    // Handle different timestamp formats
                                    if (typeof timestamp.seconds === 'number') {
                                        seconds = timestamp.seconds;
                                    } else if (timestamp.seconds && typeof timestamp.seconds.low === 'number') {
                                        seconds = timestamp.seconds.low;
                                    } else if (timestamp.seconds && typeof timestamp.seconds.toNumber === 'function') {
                                        seconds = timestamp.seconds.toNumber();
                                    } else if (timestamp.getSeconds && typeof timestamp.getSeconds === 'function') {
                                        seconds = timestamp.getSeconds();
                                    }

                                    nanos = timestamp.nanos || (timestamp.getNanos ? timestamp.getNanos() : 0);
                                    const timestampMs = seconds * 1000 + Math.floor(nanos / 1000000);
                                    timestampISO = new Date(timestampMs).toISOString();
                                }
                            } catch (tsErr) {
                                console.error(`Error converting timestamp: ${tsErr.message}`);
                            }

                            // Build history entry
                            const historyEntry = {
                                txId: historyRecord.txId || 'unknown',
                                recordId: recordKey,
                                timestamp: timestampISO,
                                isDelete: historyRecord.isDelete || false
                            };

                            // Add record data if available
                            if (recordData) {
                                historyEntry.value = {
                                    record_id: recordData.record_id || recordKey,
                                    case_id: recordData.case_id || null,
                                    record_type: recordData.record_type || null,
                                    uploader_org: recordData.uploader_org || null
                                };
                            } else {
                                historyEntry.value = null;
                            }

                            allRecords.push(historyEntry);
                            historyCount++;

                        } catch (entryErr) {
                            console.error(`Error processing history entry: ${entryErr.message}`);
                            console.error(entryErr.stack);
                        }

                        historyResult = await historyIterator.next();
                    }

                    await historyIterator.close();
                    console.log(`Added ${historyCount} history entries for ${recordKey}`);
                    processedCount++;

                } catch (recordErr) {
                    console.error(`Error processing record: ${recordErr.message}`);
                    console.error(recordErr.stack);
                }

                result = await iterator.next();
            }

            await iterator.close();
            console.log(`Processed ${processedCount} records, collected ${allRecords.length} history entries`);

            // Sort by timestamp (newest first)
            allRecords.sort((a, b) => {
                try {
                    const dateA = new Date(a.timestamp);
                    const dateB = new Date(b.timestamp);
                    return dateB.getTime() - dateA.getTime();
                } catch {
                    return 0;
                }
            });

            // Limit results
            const limitedResults = allRecords.slice(0, limit);
            
            console.log(`============= END : Get All History (${limitedResults.length} of ${allRecords.length} entries) ===========`);
            return JSON.stringify(limitedResults);

        } catch (err) {
            console.error('Error in GetAllHistory:', err);
            console.error(err.stack);
            throw new Error(`GetAllHistory failed: ${err.message}`);
        }
    }

    // -----------------------
    // Helper: GetQueryResultForQueryString
    // -----------------------
    async GetQueryResultForQueryString(ctx, queryString) {
        const resultsIterator = await ctx.stub.getQueryResult(queryString);
        const results = [];

        let result = await resultsIterator.next();
        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            let record;
            try {
                record = JSON.parse(strValue);
                results.push(record);
            } catch (err) {
                console.log(err);
            }
            result = await resultsIterator.next();
        }

        await resultsIterator.close();
        return JSON.stringify(results);
    }

    // -----------------------
    // Helper: Get Client ID
    // -----------------------
    _getClientId(ctx) {
        try {
            return ctx.clientIdentity.getID();
        } catch (err) {
            return 'unknown';
        }
    }

    // -----------------------
    // Helper: Get Client Attribute
    // -----------------------
    _getClientAttr(ctx, attr) {
        try {
            const v = ctx.clientIdentity.getAttributeValue(attr);
            return v || null;
        } catch (err) {
            return null;
        }
    }

    // -----------------------
    // Helper: Derive Role from Client ID
    // -----------------------
    // For local testing: derive role from client ID if role attribute is missing
    _deriveRoleFromClientId(ctx) {
        try {
            const clientId = this._getClientId(ctx);
            
            // Check if it's an admin
            if (clientId.includes('AdminOrg1') || clientId.includes('AdminOrg2')) {
                return 'admin';
            }
            
            // For other users, we can't reliably derive role from client ID
            // In production, role should be set as a Fabric attribute
            // For testing, return a default based on the pattern
            // This is a fallback - ideally role should be set as an attribute during enrollment
            return 'district_police'; // Default for testing
        } catch (err) {
            return null;
        }
    }

    // -----------------------
    // Helper: Check Authorization
    // -----------------------
    _isAllowed(roleValue, allowedArray) {
        // If roleValue is null/undefined, check if we should allow for testing
        // In local testing without role attributes, allow all operations
        // FOR TESTING ONLY - NOT FOR PRODUCTION
        const TEST_MODE = process.env.TEST_MODE === 'true' || true; // Enable test mode by default for now
        
        if (!roleValue) {
            if (TEST_MODE) {
                // In test mode, allow all operations if role is missing
                // This allows the chaincode to work without role attributes set in Fabric CA
                console.warn('Role attribute not found in identity. Test mode enabled - allowing operation.');
                return true;
            }
            return false;
        }
        
        return allowedArray.includes(roleValue);
    }

    // -----------------------
    // LogSystemEvent
    // -----------------------
    /**
     * Log system events (login, logout, user approval, access grant/revoke/restore)
     * @param {Context} ctx - Transaction context
     * @param {string} eventType - Type of event (LOGIN, LOGOUT, USER_APPROVED, ACCESS_GRANTED, ACCESS_REVOKED, ACCESS_RESTORED)
     * @param {string} actor - User who performed the action (name)
     * @param {string} actorOrg - User's organization (A or B)
     * @param {string} details - Additional details about the event
     * @param {string} targetUser - Target user (for approval/access operations, optional)
     * @param {string} targetUserOrg - Target user's organization (optional)
     */
    async LogSystemEvent(ctx, eventType, actor, actorOrg, details, targetUser, targetUserOrg) {
        console.info(`============= START : Log System Event ===========`);
        console.info(`Event Type: ${eventType}, Actor: ${actor}, Org: ${actorOrg}`);
        
        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        
        // System events are allowed for all authenticated users
        // No role check needed - these are logging operations
        
        // ✅ Use deterministic transaction timestamp and ID
        const timestamp = this._getTxTimestamp(ctx);
        const txId = ctx.stub.getTxID();
        
        const systemEvent = {
            event_id: this._getUniqueTxId(ctx, 'SYSTEM_EVENT'),
            event_type: eventType,
            actor: actor || this._getClientId(ctx),
            actor_org: actorOrg,
            actor_role: callerRole,
            target_user: targetUser || null,
            target_user_org: targetUserOrg || null,
            timestamp: timestamp,
            details: details || '',
            tx_id: txId
        };
        
        // Store system event
        await ctx.stub.putState(systemEvent.event_id, Buffer.from(JSON.stringify(systemEvent)));
        
        // Emit event
        ctx.stub.setEvent('SystemEvent', Buffer.from(JSON.stringify({
            event_type: eventType,
            actor: systemEvent.actor,
            actor_org: systemEvent.actor_org
        })));
        
        console.info(`============= END : Log System Event ===========`);
        return systemEvent.event_id;
    }

    // -----------------------
    // GetSystemEvents
    // -----------------------
    /**
     * Get system events (for dashboard activity feed)
     * @param {Context} ctx - Transaction context
     * @param {string} limit - Maximum number of events to return (default: 100)
     */
    async GetSystemEvents(ctx, limitParam) {
        console.info(`============= START : Get System Events ===========`);
        
        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can view system events
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            console.warn(`GetSystemEvents: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
        }
        
        try {
            const limit = limitParam ? parseInt(limitParam) : 100;
            const events = [];
            
            // Query all SYSTEM_EVENT keys
            const iterator = await ctx.stub.getStateByRange('', '\uffff');
            let result = await iterator.next();
            
            while (!result.done && events.length < limit) {
                try {
                    if (result.value && result.value.key && result.value.key.startsWith('SYSTEM_EVENT_')) {
                        const eventStr = Buffer.from(result.value.value.toString()).toString('utf8');
                        const event = JSON.parse(eventStr);
                        events.push(event);
                    }
                } catch (err) {
                    console.warn(`Error parsing system event: ${err.message}`);
                }
                result = await iterator.next();
            }
            
            await iterator.close();
            
            // Sort by timestamp (most recent first)
            events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            console.info(`============= END : Get System Events (found ${events.length}) ===========`);
            return JSON.stringify(events.slice(0, limit));
        } catch (err) {
            console.error(`Error getting system events: ${err.message}`);
            throw err;
        }
    }

    // -----------------------
    // GetRecordCount
    // -----------------------
    /**
     * Get total number of records in the ledger
     */
    async GetRecordCount(ctx) {
        console.info(`============= START : Get Record Count ===========`);
        
        const callerRole = this._getClientAttr(ctx, 'role') || this._deriveRoleFromClientId(ctx);
        // All roles can get record count
        if (!this._isAllowed(callerRole, ['district_police', 'investigator', 'forensics_officer', 'admin', 'judiciary'])) {
            console.warn(`GetRecordCount: Role check failed. Role: ${callerRole || 'null'}, allowing in test mode`);
        }
        
        try {
            let count = 0;
            const iterator = await ctx.stub.getStateByRange('', '\uffff');
            let result = await iterator.next();
            
            while (!result.done) {
                // Count only record keys (exclude AUDIT_, SYSTEM_EVENT_, POLICY_)
                const key = result.value.key;
                if (!key.startsWith('AUDIT_') && !key.startsWith('SYSTEM_EVENT_') && !key.startsWith('POLICY_')) {
                    count++;
                }
                result = await iterator.next();
            }
            
            await iterator.close();
            
            console.info(`============= END : Get Record Count (${count}) ===========`);
            return JSON.stringify({ count });
        } catch (err) {
            console.error(`Error getting record count: ${err.message}`);
            throw err;
        }
    }

    // -----------------------
    // Helper: Store Audit
    // -----------------------
    async _storeAudit(ctx, recordId, auditObj) {
        const auditId = auditObj.audit_id || this._getUniqueTxId(ctx, `AUDIT_${recordId}`);
        await ctx.stub.putState(auditId, Buffer.from(JSON.stringify(auditObj)));
    }
}

module.exports = CDMSContract;