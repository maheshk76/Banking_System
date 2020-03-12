using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WDDN_V2.Startup))]
namespace WDDN_V2
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
