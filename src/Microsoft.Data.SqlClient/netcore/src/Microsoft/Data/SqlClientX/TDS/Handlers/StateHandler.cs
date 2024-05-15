// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Data.SqlClientX.TDS.Types;

namespace Microsoft.Data.SqlClientX.TDS.Handlers
{
    internal class StateHandler : IStateHandler
    {
        private TdsParserState _currentState;

        public void UpdateState(TdsParserState newState)
        {
            _currentState = newState;
        }

        public TdsParserState GetCurrentState()
        {
            return _currentState;
        }
    }
}
