<%@ Control Language="C#" AutoEventWireup="true" CodeBehind="Buyform.ascx.cs" Inherits="myWebApplication.Buyform" %>

<h4>BUY STUFF</h4>
<asp:Label ID="lblFname" runat="server" width="100px" style="padding-bottom:5px;" Text="Firstname" />
<asp:TextBox ID="txtFname" runat="server" /><br />

<asp:Label ID="lblLname" runat="server" width="100px" style="padding-bottom:5px;" Text="Lastname" />
<asp:TextBox ID="txtLname" runat="server" /><br />

<asp:Label ID="lblAmount" runat="server" width="100px" style="padding-bottom:5px;" Text="Amount" />
<asp:TextBox ID="txtAmount" runat="server" /><br />

<asp:Button ID="btnBuy" runat="server" Text="Buy!" onclick="btnBuy_Click" />