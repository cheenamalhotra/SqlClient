﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;

namespace Microsoft.Data.SqlClientX
{
    internal sealed class SqlDiagnosticListener : DiagnosticListener
    {
        public SqlDiagnosticListener(string name) : base(name)
        {
            AssemblyLoadContext.GetLoadContext(Assembly.GetExecutingAssembly()).Unloading += SqlDiagnosticListener_Unloading;
        }

        private void SqlDiagnosticListener_Unloading(AssemblyLoadContext obj)
        {
            Dispose();
        }
    }
}
