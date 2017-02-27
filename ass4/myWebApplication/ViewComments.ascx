<%@ Control Language="C#" AutoEventWireup="true" CodeBehind="ViewComments.ascx.cs" Inherits="myWebApplication.ViewComments" %>


<asp:ListView ID="ListView1"  DataValueKey="Record" runat="server" 
    DataSourceID="SqlDataSource_Comments">

<LayoutTemplate>
    <div ID="itemPlaceholderContainer" runat="server" style="">
        <span runat="server" id="itemPlaceholder" />
    </div>
    <div style="">
        <asp:DataPager ID="DataPager1" runat="server">
            <Fields>
                <asp:NextPreviousPagerField ButtonType="Button" ShowFirstPageButton="True" 
                    ShowLastPageButton="True" />
            </Fields>
        </asp:DataPager>
    </div>
</LayoutTemplate>

    
<ItemTemplate>
<div style="border:1;width:240" >
<table width="200px" border="0" cellspacing="2" cellpadding="2">
<tr>
<td>
<b>Name:</b>
</td>
<td>
<%#Eval("Name") %>
</td>
</tr>
<tr>
<td colspan="2">
<b>Comment:</b>
</td>
</tr>
<tr>
<td colspan="2">
<%#Eval("Comment") %>
</td>
</tr>
</table>
</div>
</ItemTemplate>
    
</asp:ListView>


<asp:SqlDataSource ID="SqlDataSource_Comments" runat="server" 
    ConnectionString="<%$ ConnectionStrings:myVulnappDBConnectionString %>" 
    SelectCommand="SELECT [Record], [Name], [Comment] FROM [Table_Comments]"></asp:SqlDataSource>
