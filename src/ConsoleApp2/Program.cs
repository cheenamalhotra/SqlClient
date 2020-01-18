using System;
using Microsoft.Data.SqlClient;

namespace ConsoleApp2
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            using(SqlConnection con = new SqlConnection("Server=localhost;Integrated Security = true;"))
            {
                con.Open();
                Console.WriteLine("Connected!");
            }
        }
    }
}
