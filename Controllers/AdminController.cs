using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace WDDN_V2.Controllers
{
    public class AdminController : Controller
    {
        private DBaseEntities noti = new DBaseEntities();
        public ActionResult ManageAccount()
        {
            return View();
        }
       
        public async Task<ActionResult> Notifications(string searchString)
        {
            var data = from m in noti.Notifications
                       select m;

            if (!String.IsNullOrEmpty(searchString))
            {

                data = data.Where(s =>
                 s.UserId.Contains(searchString)
                || s.UserName.ToString().Contains(searchString)
                || s.Issue.Contains(searchString)
               
                );

            }

            return View(await data.ToListAsync());
        }
        
        [HttpPost, ActionName("Notifications")]
        [Authorize]
        [ValidateAntiForgeryToken]

        public ActionResult DeleteConfirmed(int id)
        {
          
            var tx = (from p in noti.Notifications where p.Id == id select p);
            foreach (Notification x in tx)
            {
                noti.Notifications.Remove(x);
            }

            noti.SaveChanges();
           
            return RedirectToAction("Index","Home");
        }
    }
}