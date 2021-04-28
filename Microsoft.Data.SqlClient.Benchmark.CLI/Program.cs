using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClient.Benchmark.CLI
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Any(a => a == "--profile"))
            {
                var b = new SqlBulkCopyBenchmark.IDataReaderBenchmark();
                b.BulkCopy();
                Task.Run(async () => await b.BulkCopyAsync());

                using var c = new SqlBulkCopyBenchmark.SqlDataReaderBenchmark();
                c.BulkCopy();
                Task.Run(async () => await c.BulkCopyAsync());
            }
            else
            {
                SqlBulkCopyBenchmark.RunBenchmark();
            }
        }
    }
}
