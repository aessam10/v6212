using Long.Login.Database.Entities;
using Long.Login.Network.Login;

namespace Long.Login.States
{
    public sealed class User
    {
        private const int LOGIN_EXP_SECONDS = 5000;
        private readonly TimeOut loginTimeOut;

        public User(LoginClient client, GameAccount gameAccount, Realm realm)
        {
            Client = client;
            AccountID = (uint)gameAccount.Id;
            UserName = gameAccount.UserName;
            RealmID = realm.Id;
            loginTimeOut = new(LOGIN_EXP_SECONDS);
            loginTimeOut.Update();
        }

        public Guid Guid => Client.Guid;
        public uint AccountID { get; }
        public string UserName { get; }
        public Guid RealmID { get; }
        public LoginClient Client { get; }
        public bool HasExpired => loginTimeOut.IsActive() && loginTimeOut.IsTimeOut(LOGIN_EXP_SECONDS);
    }
}
