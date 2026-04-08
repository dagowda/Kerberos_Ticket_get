using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace KerberosTGTReader
{
    class Program
    {
        const uint STATUS_SUCCESS = 0;
        const int KerbQueryTicketCacheMessage = 1;

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public int MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct KERB_TICKET_CACHE_INFO
        {
            public LSA_STRING ServerName;
            public LSA_STRING RealmName;
            public long StartTime;
            public long EndTime;
            public long RenewTime;
            public int EncryptionType;
            public uint TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public int MessageType;
            public int CountOfTickets;
        }

        [DllImport("secur32.dll", SetLastError = false)]
        static extern uint LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        static extern uint LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            ref LSA_STRING PackageName,
            out uint AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = false)]
        static extern uint LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            uint AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus);

     

        [DllImport("secur32.dll", SetLastError = false)]
        static extern uint LsaDeregisterLogonProcess(IntPtr LsaHandle);


      [DllImport("secur32.dll")]
static extern uint LsaEnumerateLogonSessions(out ulong LogonSessionCount, out IntPtr LogonSessionList);

[DllImport("secur32.dll")]
static extern uint LsaGetLogonSessionData(IntPtr LogonId, out IntPtr ppLogonSessionData);

[DllImport("secur32.dll")]
static extern uint LsaFreeReturnBuffer(IntPtr buffer);

[StructLayout(LayoutKind.Sequential)]
struct SECURITY_LOGON_SESSION_DATA
{
    public uint Size;
    public LUID LogonId;
    public LSA_STRING UserName;
    public LSA_STRING LogonDomain;
    public LSA_STRING AuthenticationPackage;
    public uint LogonType;
    public uint Session;
    public IntPtr Sid;
    public long LogonTime;
}

        static void Main(string[] args)
        {
           
            Console.WriteLine("=== Kerberos TGT Ticket Reader ===\n");

            try
            {
                List<TicketInfo> tickets = GetAllKerberosTickets();

                if (tickets.Count == 0)
                {
                    Console.WriteLine("No Kerberos tickets found.");
                    return;
                }

                Console.WriteLine(string.Format("Found {0} total ticket(s). Filtering TGTs...\n", tickets.Count));

                int tgtCount = 0;
                foreach (var ticket in tickets)
                {
                    if (ticket.ServerName.IndexOf("krbtgt", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        tgtCount++;
                        Console.WriteLine(string.Format("  User          : {0}", ticket.UserName));
                        Console.WriteLine(string.Format("--- TGT #{0} ---", tgtCount));
                        Console.WriteLine(string.Format("  Server Name   : {0}", ticket.ServerName));
                        Console.WriteLine(string.Format("  Realm         : {0}", ticket.RealmName));
                        Console.WriteLine(string.Format("  Start Time    : {0}", ticket.StartTime));
                        Console.WriteLine(string.Format("  End Time      : {0}", ticket.EndTime));
                        Console.WriteLine(string.Format("  Renew Until   : {0}", ticket.RenewTime));
                        Console.WriteLine(string.Format("  Encryption    : {0}", ticket.EncryptionType));
                        Console.WriteLine(string.Format("  Flags         : {0}", ticket.TicketFlags));
                        Console.WriteLine();
                    }
                }

                if (tgtCount == 0)
                    Console.WriteLine("No TGT tickets found (no 'krbtgt' entries).");
                else
                    Console.WriteLine(string.Format("Total TGTs found: {0}", tgtCount));
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Error: {0}", ex.Message));
            }
        }

        static List<TicketInfo> GetAllKerberosTickets()
{
    var tickets = new List<TicketInfo>();
    IntPtr lsaHandle = IntPtr.Zero;

    uint status = LsaConnectUntrusted(out lsaHandle);
    if (status != STATUS_SUCCESS)
        throw new Exception(string.Format("LsaConnectUntrusted failed: {0}", status));

    try
    {
        // Lookup Kerberos package
        string packageName = "Kerberos";
        byte[] packageNameBytes = Encoding.ASCII.GetBytes(packageName);
        LSA_STRING lsaPackageName = new LSA_STRING
        {
            Length = (ushort)packageNameBytes.Length,
            MaximumLength = (ushort)(packageNameBytes.Length + 1),
            Buffer = Marshal.AllocHGlobal(packageNameBytes.Length + 1)
        };
        Marshal.Copy(packageNameBytes, 0, lsaPackageName.Buffer, packageNameBytes.Length);
        Marshal.WriteByte(lsaPackageName.Buffer, packageNameBytes.Length, 0);

        uint authPackage;
        status = LsaLookupAuthenticationPackage(lsaHandle, ref lsaPackageName, out authPackage);
        Marshal.FreeHGlobal(lsaPackageName.Buffer);

        if (status != STATUS_SUCCESS)
            throw new Exception(string.Format("LsaLookupAuthenticationPackage failed: {0}", status));

        // Step 1: Enumerate ALL logon sessions
        ulong sessionCount;
        IntPtr sessionList;
        status = LsaEnumerateLogonSessions(out sessionCount, out sessionList);
        if (status != STATUS_SUCCESS)
            throw new Exception(string.Format("LsaEnumerateLogonSessions failed: {0}", status));

        Console.WriteLine(string.Format("Found {0} logon session(s).\n", sessionCount));

        int luidSize = Marshal.SizeOf(typeof(LUID));

        // Step 2: Loop through each session
        for (ulong i = 0; i < sessionCount; i++)
        {
            IntPtr luidPtr = IntPtr.Add(sessionList, (int)(i * (ulong)luidSize));
            LUID sessionLuid = (LUID)Marshal.PtrToStructure(luidPtr, typeof(LUID));

            // Get session info (username, domain, etc.)
            IntPtr sessionDataPtr;
            status = LsaGetLogonSessionData(luidPtr, out sessionDataPtr);
            string userName = "Unknown";
            string domain = "Unknown";

            if (status == STATUS_SUCCESS && sessionDataPtr != IntPtr.Zero)
            {
                SECURITY_LOGON_SESSION_DATA sessionData =
                    (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(
                        sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));

                if (sessionData.UserName.Buffer != IntPtr.Zero)
                    userName = Marshal.PtrToStringUni(sessionData.UserName.Buffer,
                        sessionData.UserName.Length / 2);

                if (sessionData.LogonDomain.Buffer != IntPtr.Zero)
                    domain = Marshal.PtrToStringUni(sessionData.LogonDomain.Buffer,
                        sessionData.LogonDomain.Length / 2);

                LsaFreeReturnBuffer(sessionDataPtr);
            }

            // Step 3: Query ticket cache for this session's LUID
            int requestSize = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_REQUEST));
            IntPtr requestPtr = Marshal.AllocHGlobal(requestSize);

            try
            {
                KERB_QUERY_TKT_CACHE_REQUEST request = new KERB_QUERY_TKT_CACHE_REQUEST
                {
                    MessageType = KerbQueryTicketCacheMessage,
                    LogonId = sessionLuid  // <-- use each session's LUID
                };

                Marshal.StructureToPtr(request, requestPtr, false);

                IntPtr responsePtr;
                int responseLength;
                int protocolStatus;

                status = LsaCallAuthenticationPackage(
                    lsaHandle, authPackage, requestPtr, requestSize,
                    out responsePtr, out responseLength, out protocolStatus);

                if (status == STATUS_SUCCESS && protocolStatus == 0)
                {
                    KERB_QUERY_TKT_CACHE_RESPONSE response =
                        (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(
                            responsePtr, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

                    int ticketInfoSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO));
                    int headerSize = Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
                    IntPtr ticketArrayPtr = IntPtr.Add(responsePtr, headerSize);

                    for (int t = 0; t < response.CountOfTickets; t++)
                    {
                        IntPtr ticketPtr = IntPtr.Add(ticketArrayPtr, t * ticketInfoSize);
                        KERB_TICKET_CACHE_INFO ticketInfo =
                            (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(
                                ticketPtr, typeof(KERB_TICKET_CACHE_INFO));

                        tickets.Add(new TicketInfo
                        {
                            UserName = string.Format("{0}\\{1}", domain, userName),
                            ServerName = Marshal.PtrToStringUni(ticketInfo.ServerName.Buffer,
                                ticketInfo.ServerName.Length / 2),
                            RealmName = Marshal.PtrToStringUni(ticketInfo.RealmName.Buffer,
                                ticketInfo.RealmName.Length / 2),
                            StartTime = DateTime.FromFileTime(ticketInfo.StartTime),
                            EndTime = DateTime.FromFileTime(ticketInfo.EndTime),
                            RenewTime = DateTime.FromFileTime(ticketInfo.RenewTime),
                            EncryptionType = GetEncryptionTypeName(ticketInfo.EncryptionType),
                            TicketFlags = GetTicketFlagNames(ticketInfo.TicketFlags)
                        });
                    }

                    LsaFreeReturnBuffer(responsePtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(requestPtr);
            }
        }
    }
    finally
    {
        LsaDeregisterLogonProcess(lsaHandle);
    }

    return tickets;
}
        static string GetEncryptionTypeName(int encType)
        {
            switch (encType)
            {
                case 1:  return "DES-CBC-CRC";
                case 3:  return "DES-CBC-MD5";
                case 17: return "AES128-CTS-HMAC-SHA1-96";
                case 18: return "AES256-CTS-HMAC-SHA1-96";
                case 23: return "RC4-HMAC (NTLM)";
                default: return string.Format("Unknown ({0})", encType);
            }
        }

        static string GetTicketFlagNames(uint flags)
        {
            var names = new List<string>();
            if ((flags & 0x40000000) != 0) names.Add("Forwardable");
            if ((flags & 0x20000000) != 0) names.Add("Forwarded");
            if ((flags & 0x10000000) != 0) names.Add("Proxiable");
            if ((flags & 0x08000000) != 0) names.Add("Proxy");
            if ((flags & 0x04000000) != 0) names.Add("MayPostdate");
            if ((flags & 0x02000000) != 0) names.Add("Postdated");
            if ((flags & 0x01000000) != 0) names.Add("Invalid");
            if ((flags & 0x00800000) != 0) names.Add("Renewable");
            if ((flags & 0x00400000) != 0) names.Add("Initial");
            if ((flags & 0x00200000) != 0) names.Add("PreAuthRequired");
            if ((flags & 0x00100000) != 0) names.Add("HardwareAuthRequired");
            if ((flags & 0x00020000) != 0) names.Add("OkAsDelegate");
            return names.Count > 0 ? string.Join(", ", names) : string.Format("0x{0:X8}", flags);
        }
    }

    class TicketInfo
    {
        public string UserName { get; set; }
        public string ServerName { get; set; }
        public string RealmName { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public DateTime RenewTime { get; set; }
        public string EncryptionType { get; set; }
        public string TicketFlags { get; set; }
    }
}
