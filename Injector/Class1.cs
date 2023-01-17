using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Injector2
{
    internal class Class1
    {
        static void RecursiveFunction(int n)
        {
            if (n <= 0)
            {
                return;
            }
            Console.WriteLine(n);
            RecursiveFunction(n - 1);
        }

    }
}
