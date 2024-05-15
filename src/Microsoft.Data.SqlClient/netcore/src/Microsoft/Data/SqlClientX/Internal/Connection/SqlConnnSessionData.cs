using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Data.SqlClient;

namespace Microsoft.Data.SqlClientX.Internal.Connection
{
    internal sealed class SqlConnSessionData
    {
        internal const int _maxNumberOfSessionStates = 256;
        internal uint _tdsVersion;
        internal bool _encrypted;

        internal string _database;
        internal SqlCollation _collation;
        internal string _language;

        internal string _initialDatabase;
        internal SqlCollation _initialCollation;
        internal string _initialLanguage;

        internal byte _unrecoverableStatesCount = 0;
        internal Dictionary<string, Tuple<string, string>> _resolvedAliases;

#if DEBUG
        internal bool _debugReconnectDataApplied;
#endif

        internal SqlConnSessionStateRecord[] _delta = new SqlConnSessionStateRecord[_maxNumberOfSessionStates];
        internal bool _deltaDirty = false;
        internal byte[][] _initialState = new byte[_maxNumberOfSessionStates][];

        public SqlConnSessionData(SqlConnSessionData recoveryData)
        {
            _initialDatabase = recoveryData._initialDatabase;
            _initialCollation = recoveryData._initialCollation;
            _initialLanguage = recoveryData._initialLanguage;
            _resolvedAliases = recoveryData._resolvedAliases;

            for (int i = 0; i < _maxNumberOfSessionStates; i++)
            {
                if (recoveryData._initialState[i] != null)
                {
                    _initialState[i] = (byte[])recoveryData._initialState[i].Clone();
                }
            }
        }

        public SqlConnSessionData()
        {
            _resolvedAliases = new Dictionary<string, Tuple<string, string>>(2);
        }

        public void Reset()
        {
            _database = null;
            _collation = null;
            _language = null;
            if (_deltaDirty)
            {
                Array.Clear(_delta, 0, _delta.Length);
                _deltaDirty = false;
            }
            _unrecoverableStatesCount = 0;
        }

        [Conditional("DEBUG")]
        public void AssertUnrecoverableStateCountIsCorrect()
        {
            byte unrecoverableCount = 0;
            foreach (var state in _delta)
            {
                if (state != null && !state._recoverable)
                    unrecoverableCount++;
            }
            Debug.Assert(unrecoverableCount == _unrecoverableStatesCount, "Unrecoverable count does not match");
        }
    }
    internal sealed class SqlConnSessionStateRecord
    {
        internal bool _recoverable;
        internal uint _version;
        internal int _dataLength;
        internal byte[] _data;
    }
}
