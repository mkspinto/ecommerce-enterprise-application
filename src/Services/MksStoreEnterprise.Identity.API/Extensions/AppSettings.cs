namespace MksStoreEnterprise.Identity.API.Extensions
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public int ExpirationHours { get; set; }
        public string Emitter { get; set; }
        public string ValidAt { get; set; }
    }
}