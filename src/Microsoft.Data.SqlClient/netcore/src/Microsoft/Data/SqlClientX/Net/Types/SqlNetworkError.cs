﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;

namespace Microsoft.Data.SqlClientX.Net.Types
{
    internal class SqlNetworkError
    {
        public readonly Providers provider;
        public readonly string errorMessage;
        public readonly uint nativeError;
        public readonly uint sniError;
        public readonly string function;
        public readonly uint lineNumber;
        public readonly Exception exception;

        public SqlNetworkError(Providers provider, uint nativeError, uint sniErrorCode, string errorMessage)
        {
            lineNumber = 0;
            function = string.Empty;
            this.provider = provider;
            this.nativeError = nativeError;
            sniError = sniErrorCode;
            this.errorMessage = errorMessage;
            exception = null;
        }

        public SqlNetworkError(Providers provider, uint sniErrorCode, Exception sniException, uint nativeErrorCode = 0)
        {
            lineNumber = 0;
            function = string.Empty;
            this.provider = provider;
            nativeError = nativeErrorCode;
            sniError = sniErrorCode;
            errorMessage = string.Empty;
            exception = sniException;
        }
    }
}
