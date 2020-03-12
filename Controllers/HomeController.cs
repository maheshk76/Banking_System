using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using static WDDN_V2.Controllers.ManageController;
using System.Data;
using System.Collections;
using System.Linq;
using System.Collections.Generic;
using System.Windows.Documents;
using System;

namespace WDDN_V2.Controllers
{
    public class HomeController : Controller
    {

        UsermanagerDBEntities db = new UsermanagerDBEntities();
        private DBaseEntities noti = new DBaseEntities();
        private DBases2Entities log = new DBases2Entities();
        public ActionResult Index()
        {
            string id = User.Identity.GetUserId();
            string logname = User.Identity.GetUserName();
            string name = (from x in db.AspNetUsers where x.Id == id select x.FullName).FirstOrDefault();
            ViewBag.NAME = name;
            int count = 0;
            var nots = (from x in noti.Notifications select x);
            foreach (Notification p in nots)
            {
                count++;
            }
            var ids = (from x in log.UserLogs where x.UserId==logname select x);

            List<int> l = new List<int>();
            
            var idss = (from x in log.UserLogs where x.UserId == logname select x.Id);
           
            int max =0,max1=0;
            if (ids == null)
                max = 0;
            else
            {
                foreach (var p in idss)
                {
                    l.Add(p);
                }
                for(int i=0;i<l.Count;i++) {
                    if (  i > max)
                        max1 = i;
                        }
                max = max1 - 1;
                try
                {
                    max = l[max];
                }
                catch (Exception e)
                {

                }
                
            }
            string userlog = (from x in log.UserLogs where x.UserId == logname && x.Id==max select x.Logs.ToString()).FirstOrDefault();
            TempData["UserLog"] = userlog;
            TempData.Keep("UserLog");
           TempData["nots"] = count;
            TempData.Keep("nots");
            return View();
           
        }
        public enum ManageMessageId
        {
            RequestSuccess,
            
            Error
        }
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}