// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClientX.Logging
{
    // ILogger Interface
    internal interface ILogger
    {
        public void LogError(Exception exception, string message);
        public void LogError(string message);
    }
}
