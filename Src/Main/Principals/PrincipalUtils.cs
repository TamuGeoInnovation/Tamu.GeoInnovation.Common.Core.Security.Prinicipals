using System;
using System.Security.Principal;

namespace USC.GISResearchLab.Common.Utils.Security.Principals
{
    public class PrincipalUtils
    {

        public static bool IsLoggedOn(GenericPrincipal principal)
        {
            bool ret = false;
            if (IsAuthenticated(principal))
            {
                if (!String.IsNullOrEmpty(principal.Identity.Name))
                {
                    ret = true;
                }
            }
            return ret;
        }

        public static string UserName(GenericPrincipal principal)
        {
            string ret = "";
            if (IsAuthenticated(principal))
            {
                if (!String.IsNullOrEmpty(principal.Identity.Name))
                {
                    ret = principal.Identity.Name;
                }
            }
            return ret;
        }


        public static bool IsInRole(GenericPrincipal principal, string role)
        {
            return IsInRole(principal, role, new string[] { role });
        }

        public static bool IsAuthenticated(GenericPrincipal principal)
        {
            bool ret = false;
            if (principal != null)
            {
                if (principal.Identity.IsAuthenticated)
                {
                    ret = true;
                }
            }
            return ret;
        }

        public static bool IsInRole(GenericPrincipal principal, string requiredRole, string[] roleHiearchy)
        {
            bool ret = false;
            if (IsAuthenticated(principal))
            {
                if (roleHiearchy != null)
                {
                    if (roleHiearchy.Length > 0)
                    {
                        int effectiveRoleLevel = -1;
                        int requiredRoleLevel = -1;

                        for (int i = 0; i < roleHiearchy.Length; i++)
                        {
                            string userLevel = roleHiearchy[i];

                            // IsInRole below has stopped working, explicitly test each of the roles.
                            if (principal.Identity != null)
                            {
                                if (((System.Web.Security.FormsIdentity)(principal.Identity)).Ticket.UserData != null)
                                {
                                    if (string.Compare(((System.Web.Security.FormsIdentity)(principal.Identity)).Ticket.UserData, userLevel, true) == 0)
                                    {
                                        effectiveRoleLevel = i;
                                        break;
                                    }
                                }
                            }


                            if (principal.IsInRole(userLevel))
                            {
                                effectiveRoleLevel = i;
                                break;
                            }
                        }

                        for (int i = 0; i < roleHiearchy.Length; i++)
                        {
                            string userLevel = roleHiearchy[i];
                            if (String.Compare(requiredRole, userLevel, true) == 0)
                            {
                                requiredRoleLevel = i;
                                break;
                            }
                        }

                        if (effectiveRoleLevel >= 0 && requiredRoleLevel >= 0)
                        {
                            if (effectiveRoleLevel <= requiredRoleLevel)
                            {
                                ret = true;
                            }
                        }

                    }
                }
                else
                {
                    ret = principal.IsInRole(requiredRole);
                }

            }
            return ret;
        }

        public static bool HasCapability(string requiredCapability, string capabilityString)
        {
            string[] capabilityList = capabilityString.Split('|');
            return HasCapability(requiredCapability, capabilityList);
        }
        public static bool HasCapability(string requiredCapability, string[] capabilityList)
        {
            bool ret = false;

            if (capabilityList != null)
            {
                for (int i = 0; i < capabilityList.Length; i++)
                {
                    if (String.Compare(requiredCapability, capabilityList[i], true) == 0)
                    {
                        ret = true;
                        break;
                    }
                }
            }
            return ret;
        }
    }
}
