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
using System.Data.OleDb;
using System.Data;
using System.Text;
using System.Collections;
using System.Text.RegularExpressions;



namespace ICP.KeyExchange.TestLibrary.Test


{
    [TestClass]
    public class CertificateApiTest
    {

        string post1;
        string post2;
        string post3;
        string post4;
        string aeskeyiv;
        string encryptedContent = null;
        string decryptedContent = null;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
            //BaseAddress = new Uri("http://icp-member-beta.ecpay.com.tw/")
            BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")
            // BaseAddress = new Uri("https://icp-member-beta.opay.tw/")



        };
        private readonly HttpClient _httpClient2 = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
           // BaseAddress = new Uri("http://icp-payment-beta.ecpay.com.tw/")
              BaseAddress = new Uri("https://icp-payment-stage.icashpay.com.tw/")
            // BaseAddress = new Uri("https://icp-member-beta.opay.tw/")



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
                //throw new Exception("Timestamp 有誤");
            }

            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 30 || subSec < -30)
            {
               // throw new Exception("Timestamp 誤差過大");
            }
        }

        private (long CertId, string PublicKey) getDefaultPucCert()
        {
            string url = "/api/member/Certificate/GetDefaultPucCert";

            var postResult = _httpClient.PostAsync(url, null).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
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
            aeskeyiv = aeskeyiv + json + '\n';

            using (StreamWriter writer = new StreamWriter("keyiv1.txt"))


            {


                writer.Write(aeskeyiv);

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
            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }

        [TestMethod]

        private string callNormalApi2(string url, object obj, ref string decryptContent)
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
            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }
        public void GetCellphone()
        {
            
            string strCon = "Provider=Microsoft.Jet.OLEDB.4.0;" +
                            "Data Source=C:\\Test01S111;" +
                            "Extended Properties='Excel 8.0;" +
                            "HDR=NO;" +
                            "IMEX=1'";
            OleDbConnection GetCSV = new OleDbConnection(strCon);
            GetCSV.Open();
            DataTable Table = GetCSV.GetOleDbSchemaTable(OleDbSchemaGuid.Tables, null);
            string SelectSheetName = "";
            foreach (DataRow row in Table.Rows)
            {
                SelectSheetName = (string)row["TABLE_NAME"];
                if (SelectSheetName == "SheetA$")
                {
                    OleDbCommand cmSheetA = new OleDbCommand(" SELECT * FROM [SheetA$] ", GetCSV);
                    OleDbDataReader drSheetA = cmSheetA.ExecuteReader();
                    List<string> ListSheetA = new List<string>();
                    int cnt = 0;
                    while (drSheetA.Read())
                    {
                        generateAES();
                        string url = "/app/MemberInfo/UserCodeLogin2022";
                        string url2 = "/app/TransferAccount/GetTransferToken";
                        string url3 = "/app/TransferAccount/SentTransferMsg";
                        ListSheetA.Add(drSheetA[0].ToString());
                        ListSheetA.Add(drSheetA[1].ToString());
                        ListSheetA.Add(drSheetA[2].ToString());
                        ListSheetA.Add(drSheetA[3].ToString());
                        ListSheetA.Add(drSheetA[4].ToString());
                        var request1 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            LoginTokenID = ListSheetA[2],
                            UserCode = ListSheetA[3],
                            UserPwd = "Aa123456"
                        };
                        string decryptContent1 = null;
                        string response1 = callNormalApi(url, request1, ref decryptContent1);
                        post1 = post1 + response1 + '\n';
                        using (StreamWriter writer = new StreamWriter("important1.txt"))
                        {
                            writer.WriteLine(post1);

                        }
                        var request2 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                      
           
                        };
                        string decryptContent2 = null;
                        string response2 = callNormalApi2(url2, request2, ref decryptContent2);
                        post2 = post2 + response2 + '\n';
                        post3 = response2;
                        using (StreamWriter writer = new StreamWriter("important2.txt"))
                        {
                            writer.WriteLine(post2);

                        }
                        string DecodePost;
                        string[] sArray = Regex.Split(post3,@"""", RegexOptions.IgnoreCase);
                        foreach (string i in sArray)
                        {
                            //Console.WriteLine(i.ToString());
                            //Console.Write(sArray[3]);
                            //Console.WriteLine(DecodePost);

                        }
                        DecodePost=sArray[3];
                        _aesCryptoHelper.Key = _aesKey;
                        _aesCryptoHelper.Iv = _aesIv;
                        string DecodePost2= _aesCryptoHelper.Decrypt(DecodePost);
                        string DecodePost3;
                        string[] sArray2 = Regex.Split(DecodePost2, @"""", RegexOptions.IgnoreCase);
                        foreach (string i in sArray2)
                        {  
                            //Console.WriteLine(i.ToString());
                            //Console.Write(sArray[3]);
                            //Console.WriteLine(DecodePost);

                        }
                        DecodePost3 = sArray2[3];
                        post4 = post4 + DecodePost3 + '\n';

                        using (StreamReader reader = new StreamReader("important3.txt"))
                        {
                            string fileContent = reader.ReadToEnd();
                            Console.WriteLine(fileContent);
                        }

                        string decryptedData = DecodePost3;
                        Console.WriteLine("Decrypted Data: " + decryptedData);




                        var request3 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            PayChatMID = "14083",
                            ReceivedChatMID = "14095",
                            TransferAmount = "10",
                            TradeToken = decryptedData,
                            PaymentType = "1"
                        };

                        string decryptContent3 = null;
                        string response3 = callNormalApi2(url3, request3, ref decryptContent3);
                        post4 = post4 + response3 + '\n';
                        post3 = response3;
                        using (StreamWriter writer = new StreamWriter("important3.txt"))
                        {
                            writer.WriteLine(post4);
                        }



                        //using (StreamWriter writer = new StreamWriter("StoredBarcode.txt"))
                        //{
                        //    writer.Write(post4);

                        //}
                        ListSheetA.Clear();
                        cnt++;
                        Console.WriteLine(cnt);
                }
                    drSheetA.Close();
                    GetCSV.Close();
                    Console.ReadLine();
            }
            
        }

        }




    }
}





    
