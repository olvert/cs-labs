using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace myWebApplication
{
    public partial class Buyform : System.Web.UI.UserControl
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnBuy_Click(object sender, EventArgs e)
        {
            Response.Redirect("default.aspx?page=2");
        }
    }
}