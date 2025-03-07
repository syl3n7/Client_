using System;

namespace SecureTcpClient.Models
{
    public class ServerResponse
    {
        public string Message { get; set; }
        public object Data { get; set; }

        public ServerResponse(string message, object data = null)
        {
            Message = message;
            Data = data;
        }
    }
}
