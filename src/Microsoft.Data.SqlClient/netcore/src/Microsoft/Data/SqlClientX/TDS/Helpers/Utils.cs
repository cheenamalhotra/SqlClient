using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;

namespace Microsoft.Data.SqlClientX.TDS.Helpers
{
    internal static class Utils
    {

        /// <summary>
        /// Checks if the given token is a valid TDS token
        /// </summary>
        /// <param name="token">Token to check</param>
        /// <returns>True if the token is a valid TDS token, otherwise false</returns>
        internal static bool IsValidTdsToken(byte token)
        {
            return (
                token == TdsEnums.SQLERROR ||
                token == TdsEnums.SQLINFO ||
                token == TdsEnums.SQLLOGINACK ||
                token == TdsEnums.SQLENVCHANGE ||
                token == TdsEnums.SQLRETURNVALUE ||
                token == TdsEnums.SQLRETURNSTATUS ||
                token == TdsEnums.SQLCOLNAME ||
                token == TdsEnums.SQLCOLFMT ||
                token == TdsEnums.SQLRESCOLSRCS ||
                token == TdsEnums.SQLDATACLASSIFICATION ||
                token == TdsEnums.SQLCOLMETADATA ||
                token == TdsEnums.SQLALTMETADATA ||
                token == TdsEnums.SQLTABNAME ||
                token == TdsEnums.SQLCOLINFO ||
                token == TdsEnums.SQLORDER ||
                token == TdsEnums.SQLALTROW ||
                token == TdsEnums.SQLROW ||
                token == TdsEnums.SQLNBCROW ||
                token == TdsEnums.SQLDONE ||
                token == TdsEnums.SQLDONEPROC ||
                token == TdsEnums.SQLDONEINPROC ||
                token == TdsEnums.SQLROWCRC ||
                token == TdsEnums.SQLSECLEVEL ||
                token == TdsEnums.SQLPROCID ||
                token == TdsEnums.SQLOFFSET ||
                token == TdsEnums.SQLSSPI ||
                token == TdsEnums.SQLFEATUREEXTACK ||
                token == TdsEnums.SQLSESSIONSTATE ||
                token == TdsEnums.SQLFEDAUTHINFO);
        }
    }
}
