using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
namespace ICP.KeyExchange.TestLibrary.Test
{
    [TestClass]
    public class CertificateApiTest
    {
        int i = 0;
        string enc;
        string post1;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")

            BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")
            

        };

        private readonly HttpClient _httpClient2 = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")

            BaseAddress = new Uri("https://icp-plus-stage.icashpay.com.tw")


        };


        private readonly RsaCryptoHelper _rsaCryptoHelper = new RsaCryptoHelper();
        private readonly AesCryptoHelper _aesCryptoHelper = new AesCryptoHelper();
        private string _serverPublicKey = null;
        private string _clientPublicKey = null;
        private string _clientPrivateKey = null;
        private long _aesClientCertId = -1;
        private string _aesKey = null;
        private string _aesIv = null;
        [TestMethod]
        public void GetDefaultPucCert()
        {
            getDefaultPucCert();
        }
        [TestMethod]
        public void ExchangePucCert()
        {
            exchangePucCert();
        }
        [TestMethod]
        public void GenerateAES()
        {
            generateAES();
        }
        private (string Content, string Signature) callCertificateApi(string action, long certId, string serverPublicKey, string clientPrivateKey, object obj, string certHeaderName)
        {
            string json = JsonConvert.SerializeObject(obj);
            _rsaCryptoHelper.ImportPemPublicKey(serverPublicKey);
            string encData = _rsaCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            var content = new FormUrlEncodedContent(form);
            content.Headers.Add(certHeaderName, certId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            var postResult = _httpClient.PostAsync(action, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();
            string resultSignature = headerSignature.Value?.FirstOrDefault();
            return (stringResult, resultSignature);
        }


        private void checkTimestamp(string timestamp)
        {
            if (!DateTime.TryParse(timestamp, out DateTime dt))
            {
                Console.WriteLine($"無法解析的 Timestamp：{timestamp}");
                // 或者您也可以使用其他方式記錄除錯訊息，如日誌系統
                // throw new Exception("Timestamp 有誤");
                //throw new Exception("Timestamp 有誤");
            }
            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 30 || subSec < -30)
            {
                Console.WriteLine($"Timestamp 誤差過大：{timestamp}");
                // 或者您也可以使用其他方式記錄除錯訊息，如日誌系統
                // throw new Exception("Timestamp 誤差過大");
                // throw new Exception("Timestamp 誤差過大");
            }
        }
        private (long CertId, string PublicKey) getDefaultPucCert()
        {
            string url = "/api/member/Certificate/GetDefaultPucCert";
            var postResult = _httpClient.PostAsync(url, null).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"回傳：{stringResult}");
            JObject jObj = JObject.Parse(stringResult);
            int rtnCode = jObj.Value<int>("RtnCode");
            Assert.AreEqual(1, rtnCode);
            long certId = jObj.Value<long>("DefaultPubCertID");
            string publicKey = jObj.Value<string>("DefaultPubCert");
            return (certId, publicKey);
        }
        private (ExchangePucCertResult Result, string ClientPrivateKey) exchangePucCert()
        {
            var getDefaultPucCertResult = getDefaultPucCert();
            var key = _rsaCryptoHelper.GeneratePemKey();
            var result = callCertificateApi("/api/member/Certificate/ExchangePucCert",
                                 getDefaultPucCertResult.CertId,
                                 getDefaultPucCertResult.PublicKey,
                                 key.PrivateKey,
                                 new ExchangePucCertRequest
                                 {
                                     ClientPubCert = key.PublicKey,
                                     Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                                 },
                                 "X-iCP-DefaultPubCertID");
            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }
            _rsaCryptoHelper.ImportPemPrivateKey(key.PrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            var exchangePucCertResult = JsonConvert.DeserializeObject<ExchangePucCertResult>(json);
            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            checkTimestamp(exchangePucCertResult.Timestamp);
            _clientPrivateKey = key.PrivateKey;
            _clientPublicKey = key.PublicKey;
            _serverPublicKey = exchangePucCertResult.ServerPubCert;
            return (exchangePucCertResult, key.PrivateKey);
        }
        private void generateAES()
        {
            var exchangePucCertResult = exchangePucCert();
            var result = callCertificateApi("/api/member/Certificate/GenerateAES",
                                 exchangePucCertResult.Result.ServerPubCertID,
                                 exchangePucCertResult.Result.ServerPubCert,
                                 exchangePucCertResult.ClientPrivateKey,
            new BaseAuthorizationApiRequest
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
            },
                                 "X-iCP-ServerPubCertID");
            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }
            _rsaCryptoHelper.ImportPemPrivateKey(exchangePucCertResult.ClientPrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            using (StreamWriter writer = new StreamWriter("keyiv1.txt"))
            {
                writer.WriteLine(json);
                Console.WriteLine("168168168");
                Console.WriteLine(json);
            }
            var generateAesResult = JsonConvert.DeserializeObject<GenerateAesResult>(json);
            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.Result.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            checkTimestamp(generateAesResult.Timestamp);
            _aesClientCertId = generateAesResult.EncKeyID;
            _aesKey = generateAesResult.AES_Key;
            _aesIv = generateAesResult.AES_IV;

        
        }
        private string callNormalApi(string url, object obj, ref string decryptContent)
        {
            string json = JsonConvert.SerializeObject(obj);
            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            var content = new FormUrlEncodedContent(form);
            content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            string s = _aesClientCertId.ToString();
            string a = signature;
            var postResult = _httpClient.PostAsync(url, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();
            string resultSignature = headerSignature.Value?.FirstOrDefault();
            _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            JToken jToken = JToken.Parse(stringResult);
            if (jToken["RtnCode"].Value<int>() != 1)
            {
                throw new Exception(jToken["RtnMsg"].Value<string>());
            }
            decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());
            string encryptedData = jToken["EncData"].Value<string>();

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string decryptedData = _aesCryptoHelper.Decrypt(encryptedData);
            decryptContent = decryptedData;
            Console.WriteLine("16616166");
            Console.WriteLine(decryptContent);

            //// 提取LoginTokenID的值
            //int startIndex = decryptedData.IndexOf("\"LoginTokenID\":\"") + "\"LoginTokenID\":\"".Length;
            //int endIndex = decryptedData.IndexOf(',', startIndex);
            //string loginTokenID = decryptedData.Substring(startIndex, endIndex - startIndex);

            //// 输出LoginTokenID的值
            //Console.WriteLine(loginTokenID);

            //// 将LoginTokenID写入token.txt文件
            //File.WriteAllText("token.txt", loginTokenID);


            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }

        private string callNormalApi1(string url, object obj, ref string decryptContent)
        {
            string json = JsonConvert.SerializeObject(obj);
            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            var content = new FormUrlEncodedContent(form);
            content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            string s = _aesClientCertId.ToString();
            string a = signature;
            var postResult = _httpClient2.PostAsync(url, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();
            string resultSignature = headerSignature.Value?.FirstOrDefault();
            _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            JToken jToken = JToken.Parse(stringResult);
            if (jToken["RtnCode"].Value<int>() != 1)
            {
                throw new Exception(jToken["RtnMsg"].Value<string>());
            }
            decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());
            string encryptedData = jToken["EncData"].Value<string>();

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string decryptedData = _aesCryptoHelper.Decrypt(encryptedData);
            decryptContent = decryptedData;
            Console.WriteLine("15515155");
            Console.WriteLine(decryptContent);

            //// 提取LoginTokenID的值
            //int startIndex = decryptedData.IndexOf("\"LoginTokenID\":\"") + "\"LoginTokenID\":\"".Length;
            //int endIndex = decryptedData.IndexOf(',', startIndex);
            //string loginTokenID = decryptedData.Substring(startIndex, endIndex - startIndex);

            //// 输出LoginTokenID的值
            //Console.WriteLine(loginTokenID);

            //// 将LoginTokenID写入token.txt文件
            //File.WriteAllText("token.txt", loginTokenID);


            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }

        private string _postDataFileName;
        private string callNormalApiL(string url, object obj, ref string decryptContent, string postDataFileName)

        {
            _postDataFileName = postDataFileName; // 設置類級別變量的值
            string json = JsonConvert.SerializeObject(obj);
            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            string s = _aesClientCertId.ToString();
            string postData = $"{s},{signature},{encData}";
            string filePath = Path.Combine("C:\\testicashapi\\LpostData", postDataFileName);
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine(postData);
            }
            return post1;
        }

        [TestMethod]
        public void GetCellphone()
        {
            generateAES();
            // string url = "/MemberInfo/SendOTP";
               string url = "/MemberInfo/VerifyAccount";
               string url1 = "/MemberInfo/GetMemberData";
               string url2 = "/MemberInfo/VerifySecurityCode";
               string url3 = "/MemberInfo/VerifyDeviceID";
               string url4 = "/MemberInfo/SetDeviceID";
               string url5 = "/MemberInfo/GetMemberStatus";
               string url6 = "/MemberInfo/MemberLogin";
               string url7 = "/app/MemberInfo/GetLoginInfo";
              string url71 = "/app/Payment/GetAvailableBalance";
            // string url1 = "/app/Payment/ParserQrCode";
            //  string url1 = "/app/Payment/CreateBarcode";
            //   string url = "/app/MemberInfo/SendAuthSMS";
            //string url = "/app/MemberInfo/UserCodeLogin2022";
            var request1 = new
            {
                 Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //  LoginType = 1,
               // UserCode = "icp00921",
               // UserPwd = "Aa123456"
               // CellPhone = "0910000003",
                //SMSAuthType = 1,
               // AuthCode = "771058",
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt"),
                Account = "tester1851"
                //  AuthCode = "111111"
                // SMSAuthCode = System.IO.File.ReadAllText(@"C:\SendAuthSMS-and change mobile\ConsoleApp1\bin\Debug\AutoCode.txt")
                //CellPhone = "0908009004",
                //  SMSAuthType = 5
            };
            string decryptContent1 = null;
            string response1 = callNormalApi(url, request1, ref decryptContent1);
            Console.WriteLine("VeriyfAccount");
            Console.WriteLine(response1);

            var request2 = new
            {
                
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt"),
                MemberDataType = "1"

            };

            string decryptContent2 = null;
            string response2 = callNormalApi(url1, request2, ref decryptContent2);
            Console.WriteLine("GetMemberData");
            Console.WriteLine(response2);

            var request3 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                IsSimulator = "0",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt"),
                CodeType = 0,
                SecurityCode = "246790"

            };
            string decryptContent3 = null;
            string response3 = callNormalApi(url2, request3, ref decryptContent3);
            Console.WriteLine("VerifySecurityCode");
            Console.WriteLine(response3);

            var request4 = new
            {
               
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
 
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt")


            };

            string decryptContent4 = null;
            string response4 = callNormalApi(url3, request4, ref decryptContent4);
            Console.WriteLine("VerifyDeviceID");
            Console.WriteLine(response4);

            var request5 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"), 
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt"),
                IDNumber = "A176460182"

               
            };
            string decryptContent5 = null;
            string response5 = callNormalApi(url4, request5, ref decryptContent5);
            Console.WriteLine("SetDeviceID");
            Console.WriteLine(response5);

            var request6 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                IsSimulator = "0",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt")

            };
            string decryptContent6 = null;
            string response6 = callNormalApi(url5, request6, ref decryptContent6);
            Console.WriteLine("GetMemberStatus");
            Console.WriteLine(response6);

            var request7 = new
            {
                
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                Vers = "3.0.1.137",
                DeviceInfo = "Pixel 7bb",
                DeviceID = "b4f194a32647b4f5",
                OS = "2",
                OSVersion = "13",
                AppName = "icashpay2023",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NewICPLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt")


            };

            string decryptContent7 = null;
            string response7 = callNormalApi(url6, request7, ref decryptContent7);
            Console.WriteLine("MemberLogin");
            Console.WriteLine(response7);

            var request8 = new
            {

                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),



            };

            string decryptContent8 = null;
            string response8 = callNormalApi(url7, request8, ref decryptContent8);
            Console.WriteLine("GetLoginInfo");
            Console.WriteLine(response8);

            var request9 = new
            {

                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),



            };

            string decryptContent9 = null;
            string response9 = callNormalApiL(url71, request9, ref decryptContent9,"postData2.txt");
            //Console.WriteLine("GetLoginInfo");
            //Console.WriteLine(response9);




        }
    }
}
