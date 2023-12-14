using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;
using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using LinqToExcel;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Data.OleDb;
using System.Data;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Test
{
    [TestClass]
    public class CertificateApiTest
    {
        string post;
        string post1;
        string post2;
        string post3;
        string post4;
        string post5;
        string aeskeyiv;
        private readonly HttpClient _httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")
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
            if (subSec > 15 || subSec < -15)
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
            {
                aeskeyiv = aeskeyiv + json + '\n';
                using (StreamWriter writer = new StreamWriter("keyiv1.txt"))

                {
                    writer.WriteLine(aeskeyiv);
                }
                string filePath = "keyiv1.txt";
                string keyIvData = File.ReadAllText(filePath);
                Console.WriteLine(keyIvData);
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



        private string callNormalApi(string url, object obj, ref string decryptContent, string postDataFileName)

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
            string filePath = Path.Combine("C:\\testicashapi\\postData", postDataFileName);
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine(postData);
            }
            return post1;
        }


        private string callNormalApip(string url, object obj, ref string decryptContent)
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

            // 提取FingerPrintPwd的值
            int startIndex = decryptedData.IndexOf("\"FingerPrintPwd\":\"") + "\"FingerPrintPwd\":\"".Length;
            int endIndex = decryptedData.IndexOf(',', startIndex);
            string FingerPrintPwd = decryptedData.Substring(startIndex, endIndex - startIndex);

            // 输出LoginTokenID的值
            Console.WriteLine(FingerPrintPwd);

            // 将LoginTokenID写入token.txt文件
            File.WriteAllText("FingerPrintPwd.txt", FingerPrintPwd);


            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }
        public void GetCellphone()
        {
            int ta = 0;
            ////設定讀取的Excel屬性
            string strCon = "Provider=Microsoft.Jet.OLEDB.4.0;" +
            //路徑(檔案讀取路徑)
            "Data Source=C:\\Test01S112.xls;" +
            //選擇Excel版本
            //Excel 12.0 針對Excel 2010、2007版本(OLEDB.12.0)
            //Excel 8.0 針對Excel 97-2003版本(OLEDB.4.0)
            //Excel 5.0 針對Excel 97(OLEDB.4.0)
            "Extended Properties='Excel 8.0;" +
            //開頭是否為資料
            //若指定值為 Yes，代表 Excel 檔中的工作表第一列是欄位名稱，oleDB直接從第二列讀取
            //若指定值為 No，代表 Excel 檔中的工作表第一列就是資料了，沒有欄位名稱，oleDB直接從第一列讀取
            "HDR=NO;" +
            //IMEX=0 為「匯出模式」，能對檔案進行寫入的動作。
            //IMEX=1 為「匯入模式」，能對檔案進行讀取的動作。
            //IMEX=2 為「連結模式」，能對檔案進行讀取與寫入的動作。
            "IMEX=1'";
            /*步驟2：依照Excel的屬性及路徑開啟檔案*/
            //Excel路徑及相關資訊匯入
            OleDbConnection GetXLS = new OleDbConnection(strCon);
            //打開檔案
            GetXLS.Open();
            /*步驟3：搜尋此Excel的所有工作表，找到特定工作表進行讀檔，並將其資料存入List*/
            //搜尋xls的工作表(工作表名稱需要加$字串)
            DataTable Table = GetXLS.GetOleDbSchemaTable(OleDbSchemaGuid.Tables, null);
            //查詢此Excel所有的工作表名稱
            string SelectSheetName = "";
            foreach (DataRow row in Table.Rows)
            {
                //抓取Xls各個Sheet的名稱(+'$')-有的名稱需要加名稱''，有的不用
                SelectSheetName = (string)row["TABLE_NAME"];
                //工作表名稱有特殊字元、空格，需加'工作表名稱$'，ex：'Sheet_A$'
                //工作表名稱沒有特殊字元、空格，需加工作表名稱$，ex：SheetA$
                //所有工作表名稱為Sheet1，讀取此工作表的內容
                if (SelectSheetName == "SheetA$")
                {
                    //select 工作表名稱
                    OleDbCommand cmSheetA = new OleDbCommand(" SELECT * FROM [SheetA$] ", GetXLS);
                    OleDbDataReader drSheetA = cmSheetA.ExecuteReader();
                    //讀取工作表SheetA資料
                    List<string> ListSheetA = new List<string>();
                    int cnt = 0;
                    while (drSheetA.Read())
                    {
                        //for (i = 1; i <= 20; i++)
                        //{
                        generateAES();
                        //  string url = "/api/member/MemberInfo/getCellphone";
                        string url = "/app/MemberInfo/UserCodeLogin2022";
                     
                        //工作表SheetA的資料存入List
                        ListSheetA.Add(drSheetA[0].ToString());
                        ListSheetA.Add(drSheetA[1].ToString());
                        ListSheetA.Add(drSheetA[2].ToString());
                        ListSheetA.Add(drSheetA[3].ToString());
                        ListSheetA.Add(drSheetA[4].ToString());
                        var request1 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            LoginType = "1",
                            UserCode = ListSheetA[3],
                            UserPwd = "Aa123456"
                        };
                        string decryptContent1 = null;
                        string response1 = callNormalApi(url, request1, ref decryptContent1, "postData1.txt");

                        var request2 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        };
                        string decryptContent2 = null;
                        string response2 = callNormalApi(url, request2, ref decryptContent2, "postData2.txt");
                       
                        var request3 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            PaymentType = "2",
                            PayID = "20090000000022427"
                        };
                        string decryptContent3 = null;
                        string response3 = callNormalApi(url, request3, ref decryptContent3, "postData3.txt");
                        var request4 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankInfoType = "1"
                        };
                        string decryptContent4 = null;
                        string response4 = callNormalApi(url, request4, ref decryptContent4, "postData4.txt");

                        var request5 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankType = "1",
                            BankCode = "009"
                        };
                        string decryptContent5 = null;
                        string response5 = callNormalApi(url, request5, ref decryptContent5, "postData5.txt");
                         
                        var request51 = new
                         {
                             Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                             BankType = "2",
                             BankCode = "048"
                         };
                        string decryptContent51 = null;
                        string response51 = callNormalApi(url, request51, ref decryptContent51, "postData5_1.txt");

                        var request6 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        };
                        string decryptContent6 = null;
                        string response6 = callNormalApi(url, request6, ref decryptContent6, "postData6.txt");
                       
                        var agreeItems = new[]
                        {
                            //new { AgreeType = 1, AgreeStatus = 1 },
                            //new { AgreeType = 2, AgreeStatus = 0 },
                            //new { AgreeType = 3, AgreeStatus = 2 },
                            new { AgreeType = 4, AgreeStatus = 1 }
                        };
                        var request7 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            AgreeItems = agreeItems
                        };
                        string decryptContent7 = null;
                        string response7 = callNormalApi(url, request7, ref decryptContent7, "postData7.txt");


                        Random random = new Random();
                        string lettersAndNumbers = "abcdefghijklmnopqrstuvwxyz0123456789";
                        string randomString = new string(Enumerable.Repeat(lettersAndNumbers, 8)
                            .Select(s => s[random.Next(s.Length)]).ToArray());
                        var request8 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            NickName = randomString
                        };
                        string decryptContent8 = null;
                        string response8 = callNormalApi(url, request8, ref decryptContent8, "postData8.txt");

                        var request9 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            NickName = "^&*()"
                        };
                        string decryptContent9 = null;
                        string response9 = callNormalApi(url, request9, ref decryptContent9, "postData9.txt");

                        var request10 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            AccountType = "1"
                        };
                        string decryptContent10 = null;
                        string response10 = callNormalApi(url, request10, ref decryptContent10, "postData10.txt");

                        var request11 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            AccountType = "2"
                        };
                        string decryptContent11 = null;
                        string response11 = callNormalApi(url, request11, ref decryptContent11, "postData11.txt");

                        var request12 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            UserCode = ListSheetA[3],
                            LoginPwd = "Aa123456",
                            ConfirmLoginPwd = "Aa123456"
                        };
                        string decryptContent12 = null;
                        string response12 = callNormalApi(url, request12, ref decryptContent12, "postData12.txt");


                        var request13 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                           
                        };
                        string decryptContent13 = null;
                        string response13 = callNormalApi(url, request13, ref decryptContent13, "postData13.txt");


                        var request14 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent14 = null;
                        string response14 = callNormalApi(url, request14, ref decryptContent14, "postData14.txt");


                        var request15 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent15 = null;
                        string response15 = callNormalApi(url, request15, ref decryptContent15, "postData15.txt");


                        var request16 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent16 = null;
                        string response16 = callNormalApi(url, request16, ref decryptContent16, "postData16.txt");

                        var request17 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            CarrierNumber = "/AAAA",
                            VerificationCode = "Test1234"

                        };
                        string decryptContent17 = null;
                        string response17 = callNormalApi(url, request17, ref decryptContent17, "postData17.txt");


                        var request18 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent18 = null;
                        string response18 = callNormalApi(url, request18, ref decryptContent18, "postData18.txt");

                        var request19 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent19 = null;
                        string response19 = callNormalApi(url, request19, ref decryptContent19, "postData19.txt");


                        var request20 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            Amount = 100,
                            TopUpType = 1

                        };
                        string decryptContent20 = null;
                        string response20 = callNormalApi(url, request20, ref decryptContent20, "postData20.txt");

                        var request21 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankCode = "009",
                            BankAccout = "50509500179600",
                            AccountID = 21207,
                            Amount = 130,
                            AgreeLevelUp = true



                        };
                        string decryptContent21 = null;
                        string response21 = callNormalApi(url, request21, ref decryptContent21, "postData21.txt");


                        var request22 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                           

                        };
                        string decryptContent22 = null;
                        string response22 = callNormalApi(url, request22, ref decryptContent22, "postData22.txt");


                        var request23 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")


                        };
                        string decryptContent23 = null;
                        string response23 = callNormalApi(url, request23, ref decryptContent23, "postData23.txt");

                        var request24 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            isGetAll = true


                        };
                        string decryptContent24 = null;
                        string response24 = callNormalApi(url, request24, ref decryptContent24, "postData24.txt");


                        var request25 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                        


                        };
                        string decryptContent25 = null;
                        string response25 = callNormalApi(url, request25, ref decryptContent25, "postData25.txt");

                        var request26 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")



                        };
                        string decryptContent26 = null;
                        string response26 = callNormalApi(url, request26, ref decryptContent26, "postData26.txt");

                        var request27 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent27 = null;
                        string response27 = callNormalApi(url, request27, ref decryptContent27, "postData27.txt");

                        var request28 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

                        };
                        string decryptContent28 = null;
                        string response28 = callNormalApi(url, request28, ref decryptContent28, "postData28.txt");

                        var request29 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            CellPhone = "0908009004"

                        };
                        string decryptContent29 = null;
                        string response29 = callNormalApi(url, request29, ref decryptContent29, "postData29.txt");


                        var request30 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                         

                        };
                        string decryptContent30 = null;
                        string response30 = callNormalApi(url, request30, ref decryptContent30, "postData30.txt");



                        var request31 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")


                        };
                        string decryptContent31 = null;
                        string response31 = callNormalApi(url, request31, ref decryptContent31, "postData31.txt");

                        var request32 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankCode  = "009",
                            AccountID = "21207",
                            Amount = "100"


                        };
                        string decryptContent32 = null;
                        string response32 = callNormalApi(url, request32, ref decryptContent32, "postData32.txt");


                        var request33 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankCode = "009",
                            Amount = "100"


                        };
                        string decryptContent33 = null;
                        string response33 = callNormalApi(url, request33, ref decryptContent33, "postData33.txt");


                        var request34 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            ChangeOpPointSwitch = "N"


                        };
                        string decryptContent34 = null;
                        string response34 = callNormalApi(url, request34, ref decryptContent34, "postData34.txt");

                        var request35 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            Status = true


                        };
                        string decryptContent35 = null;
                        string response35 = callNormalApi(url, request35, ref decryptContent35, "postData35.txt");


                        var request37 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            MerchantID = "10512932",
                            Amount = "1",
                            PayID = "11682211000012808",
                            Mission ="",
                            Team_number ="",
                            MerchantTradeNo = "2023070514204"+DateTime.Now.ToString("yyyy /MM/dd HH:mm:ss"),
                            StoreID = "Dev2-Test",
                            StoreName = "Dev2-Test"


                        };
                        string decryptContent37 = null;
                        string response37 = callNormalApi(url, request37, ref decryptContent37, "postData37.txt");


                        var request38 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            MsgID = 0,
                            Type = 1,
                            Count = 100



                        };
                        string decryptContent38 = null;
                        string response38 = callNormalApi(url, request38, ref decryptContent38, "postData38.txt");

                        var request39 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            MerchantTradeNo = "202306210922310000"




                        };
                        string decryptContent39 = null;
                        string response39 = callNormalApi(url, request39, ref decryptContent39, "postData39.txt");







                        //var request4 = new
                        //    {
                        //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        //        BankInfoType = "1"
                        //    };
                        //    string decryptContent4 = null;
                        //    string response4 = callNormalApi4(url, request4, ref decryptContent4);
                        //    using (StreamWriter writer = new StreamWriter("important44.txt"))
                        //    {
                        //        writer.WriteLine(response4);
                        //        writer.Dispose();
                        //    }
                        //    var request5 = new
                        //    {
                        //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        //        BankType = "1",
                        //        BankCode = "007"
                        //    };
                        //    string decryptContent5 = null;
                        //    string response5 = callNormalApi5(url, request5, ref decryptContent5);
                        //    using (StreamWriter writer = new StreamWriter("important55.txt"))
                        //    {
                        //        writer.WriteLine(response5);
                        //        writer.Dispose();
                        //    }
                        //    var request6 = new
                        //    {
                        //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        //    };
                        //    string decryptContent6 = null;
                        //    string response6 = callNormalApi6(url, request6, ref decryptContent6);
                        //    using (StreamWriter writer = new StreamWriter("important66.txt"))
                        //    {
                        //        writer.WriteLine(response5);
                        //        writer.Dispose();
                        //    }
                        // Console.WriteLine(j1);
                        //  }
                        //ListSheetA.Add(drSheetA[0].ToString());
                        //ListSheetA.Add(drSheetA[1].ToString());
                        //ListSheetA.Add(drSheetA[2].ToString());
                        //ListSheetA.Add(drSheetA[3].ToString());
                        //ListSheetA.Add(drSheetA[4].ToString());
                        // Console.WriteLine(ListSheetA[0]+" "+ListSheetA[1]+" "+ ListSheetA[2]+" "+ ListSheetA[3]+" "+ ListSheetA[4]);
                        using (StreamWriter writer = new StreamWriter("end.txt"))
                        {
                            writer.WriteLine(ListSheetA[0] + " " + "0" + ListSheetA[1] + " " + ListSheetA[2] + " " + ListSheetA[3] + " " + ListSheetA[4]);
                        }
                        ListSheetA.Clear();
                        cnt++;
                        ta++;
                        Console.WriteLine(ta);
                    }
                    //Console.WriteLine(ListSheetA[1]);
                    /*步驟4：關閉檔案*/
                    //結束關閉讀檔(必要，不關會有error)
                    drSheetA.Close();
                    GetXLS.Close();
                    Console.ReadLine();
                }
            }
        }
    }
}
