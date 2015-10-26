using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.OAuth.Adfs
{
    internal static class AdfsHelper
    {
        public static string GetSubject(dynamic jsonObject)
        {
            return Value<string>(jsonObject, "sub");
        }

        public static T Value<T>(dynamic jsonObject, string key)
        {
            if (jsonObject == null) throw new ArgumentNullException("jsonObject");

            return jsonObject.ContainsKey(key) ? (T)jsonObject[key] : default(T);
        }

        public static T Value<T>(dynamic jsonObject, string key, Func<T> defaultFactory)
        {
            if (jsonObject == null) throw new ArgumentNullException("jsonObject");

            return jsonObject.ContainsKey(key) ? (T)jsonObject[key] : defaultFactory();
        }
    }
}
