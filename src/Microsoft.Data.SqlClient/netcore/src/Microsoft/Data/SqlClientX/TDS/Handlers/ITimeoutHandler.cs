﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClientX.TDS.Handlers
{
    internal interface ITimeoutHandler
    {
        public Task<bool> OnTimeoutAsync(int expectedState, int targetState);
    }
}
