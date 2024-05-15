// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Microsoft.Data.SqlClientX.TDS.Types
{
    internal class NetworkResult
    {
        private readonly bool _result;

        public NetworkResult(bool result) {
            _result = result;
        }

        public bool Result => _result;
    }
}
