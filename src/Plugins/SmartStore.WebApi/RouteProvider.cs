using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;
using SmartStore.Web.Framework.Routing;
using SmartStore.Web.Framework.WebApi;

namespace SmartStore.WebApi
{
    public partial class RouteProvider : IRouteProvider
    {
        public void RegisterRoutes(RouteCollection routes)
        {

            SwaggerConfig.Register();


            routes.MapHttpRoute("WebApi.ExtraApi", "api/{controller}/{action}/{id}",
                new { controller = "Home", action = "Index", id = RouteParameter.Optional });


        }


        public int Priority
        {
            get
            {
                return 0;
            }
        }
    }
}
