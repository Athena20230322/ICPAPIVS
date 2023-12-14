using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;
using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
            // BaseAddress = new Uri("https://member.icashpay.com.tw/")


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
                throw new Exception("Timestamp 有誤");
            }
            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 30 || subSec < -30)
            {
                throw new Exception("Timestamp 誤差過大");
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

            using (StreamWriter writer = new StreamWriter("exchangepuc.txt"))
            {
                writer.WriteLine(getDefaultPucCertResult);
                Console.WriteLine("112111");
                writer.WriteLine(key);
                Console.WriteLine("112112");
            
            }

            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }
            _rsaCryptoHelper.ImportPemPrivateKey(key.PrivateKey);

            using (StreamWriter writer = new StreamWriter("nnnnrsa.txt"))
            {
                writer.WriteLine(_rsaCryptoHelper);
                Console.WriteLine("169169169");
                Console.WriteLine(_rsaCryptoHelper);
            }


            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
        
            Console.WriteLine("16788888");
            Console.WriteLine(json);

            using (StreamWriter writer = new StreamWriter("rsa.txt"))
            {
                writer.WriteLine(json);
                Console.WriteLine("167167167");
                Console.WriteLine(json);
            }
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
        private string _postDataFileName;
        private string callNormalApiN(string url, object obj, ref string decryptContent, string postDataFileName)

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
            string filePath = Path.Combine("C:\\testicashapi\\npostData", postDataFileName);
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine(postData);
            }
            return post1;
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
        [TestMethod]
        public void GetCellphone()
        {
            generateAES();
            // string url = "/MemberInfo/SendOTP";
           //    string url = "/app/MemberInfo/CheckIsOP";
            // string url1 = "/app/Payment/ParserQrCode";
            //  string url1 = "/app/Payment/CreateBarcode";
          
            string url1 = "/app/MemberInfo/CheckIsUpdate";
            string url2 = "/app/MemberInfo/getAppXmlSetting";
            string url3 = "/app/MemberInfo/GetMaintainStatus";
           // string url4 = "/app/MemberInfo/GetLoginInfo";
            string url5 = "/app/MemberInfo/GetAPPAd";
            var request1 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                VersionCode = "3.0.1.137"
        
            };
            string decryptContent1 = null;
            string response1 = callNormalApiN(url1, request1, ref decryptContent1,"postData1.txt");
           // Console.WriteLine("Notlogined1");
          //  Console.WriteLine(response1);

            var request2 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),

                XmlVersion = "1"
               
            };
            string decryptContent2 = null;
            string response2 = callNormalApiN(url2, request2, ref decryptContent2,"postData2.txt");
           // Console.WriteLine("Notlogined2");
           // Console.WriteLine(response2);

            var request3 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),

              //  XmlVersion = "1"

            };
            string decryptContent3 = null;
            string response3 = callNormalApiN(url3, request3, ref decryptContent3,"postData3.txt");
          


            var request5 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "0"

            };
            string decryptcontent5 = null;
            string response5 = callNormalApiN(url5, request5, ref decryptcontent5, "postData5_0.txt");
          

            var request6 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "1"

            };
            string decryptcontent6 = null;
            string response6 = callNormalApiN(url5, request6, ref decryptcontent6, "postData5_1.txt");

            var request7 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "2"

            };
            string decryptcontent7 = null;
            string response7 = callNormalApiN(url5, request7, ref decryptcontent7, "postData5_2.txt");

            var request8 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "3"

            };
            string decryptcontent8 = null;
            string response8 = callNormalApiN(url5, request8, ref decryptcontent8, "postData5_3.txt");

            var request9 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "4"

            };
            string decryptcontent9 = null;
            string response9 = callNormalApiN(url5, request9, ref decryptcontent9, "postData5_4.txt");

            var request10 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "5"

            };
            string decryptcontent10 = null;
            string response10 = callNormalApiN(url5, request10, ref decryptcontent10, "postData5_5.txt");

            var request11 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "6"

            };
            string decryptcontent11 = null;
            string response11 = callNormalApiN(url5, request11, ref decryptcontent11, "postData5_6.txt");

            var request12 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "7"

            };
            string decryptcontent12 = null;
            string response12 = callNormalApiN(url5, request12, ref decryptcontent12, "postData5_7.txt");

            var request13 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                adtype = "8"

            };
            string decryptcontent13 = null;
            string response13 = callNormalApiN(url5, request13, ref decryptcontent13, "postData5_8.txt");





        }
    }
}
