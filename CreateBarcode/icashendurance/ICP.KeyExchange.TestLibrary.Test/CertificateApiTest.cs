using System;
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
            
            string s = _aesClientCertId.ToString();

            string postData1 = $"{s},{signature},{encData}";
            using (StreamWriter writer = new StreamWriter("postData1.txt"))
            {
                writer.WriteLine(postData1);
            }

            //string a = signature;

            //// post = post + s + ',' + a + ',' + encData + '\n';

            //string post1 = s;
            //string post2 = a;
            //string post3 = encData;

            //post 未送出的
            //using (StreamWriter writer1 = new StreamWriter("post1.txt"))
            //{
            //    writer1.WriteLine(post1);
            //}
            //using (StreamWriter writer2 = new StreamWriter("post2.txt"))
            //{
            //    writer2.WriteLine(post2);
            //}
            //using (StreamWriter writer3 = new StreamWriter("post3.txt"))
            //{
            //    writer3.WriteLine(post3);
            //}
            Console.WriteLine("X-iCP-123");
            return post;     

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
            
            string s = _aesClientCertId.ToString();
            string postData2 = $"{s},{signature},{encData}";
            using (StreamWriter writer = new StreamWriter("postData2.txt"))
            {
                writer.WriteLine(postData2);
            }

            // string a = signature;

            // post1 = post1 + s + ',' + a + ',' + encData + '\n';

            // string post4 = s;
            //  string post5 = a;
            // string post6 = encData;

            //post 未送出的
            //using (StreamWriter writer4 = new StreamWriter("post4.txt"))
            // {
            //    writer4.WriteLine(post4);
            // }
            // using (StreamWriter writer5 = new StreamWriter("post5.txt"))
            // {
            //     writer5.WriteLine(post5);
            // }
            // using (StreamWriter writer6 = new StreamWriter("post6.txt"))
            // {
            //    writer6.WriteLine(post6);
            // }
            Console.WriteLine("X-iCP-123");
            return post1;    

        }

        private string callNormalApi3(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
          
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            string s = _aesClientCertId.ToString();
            string postData3 = $"{s},{signature},{encData}";
            using (StreamWriter writer = new StreamWriter("postData3.txt"))
            {
                writer.WriteLine(postData3);
            }

            //string a = signature;


            //string post7 = s;
            //string post8 = a;
            //string post9 = encData;

            //post 未送出的
            //using (StreamWriter writer7 = new StreamWriter("post7.txt"))
            //{
            //    writer7.WriteLine(post7);
            //}
            //using (StreamWriter writer8 = new StreamWriter("post8.txt"))
            //{
            //    writer8.WriteLine(post8);
            //}
            //using (StreamWriter writer9 = new StreamWriter("post9.txt"))
            //{
            //    writer9.WriteLine(post9);
            //}
            Console.WriteLine("X-iCP-123");
            return post2;

            }


        private string callNormalApi4(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);

            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            string s = _aesClientCertId.ToString();
            string postData4 = $"{s},{signature},{encData}";
            using (StreamWriter writer = new StreamWriter("postData4.txt"))
            {
                writer.WriteLine(postData4);
            }

           
            Console.WriteLine("X-iCP-123");
            return post3;
        }


        private string callNormalApi5(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);

            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            string s = _aesClientCertId.ToString();
            string postData5 = $"{s},{signature},{encData}";
            using (StreamWriter writer = new StreamWriter("postData5.txt"))
            {
                writer.WriteLine(postData5);
            }


            Console.WriteLine("X-iCP-123");
            return post4;
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
                            //Timestamp = DateTime.Now.ToString("2019/06/20 15:30:00"),

                            LoginType = "1",
                            UserCode = ListSheetA[3],
                            UserPwd = "Aa123456"

                            // SMSAuthType = "1"
                        };
                        string decryptContent1 = null;
                        string response1 = callNormalApi(url, request1, ref decryptContent1);
                        using (StreamWriter writer = new StreamWriter("important11.txt"))
                        {
                            writer.WriteLine(response1);
                            writer.Dispose();
                        }

                       // for (int j1 = 0; j1 < 5; j1++)


                      //  {


                            var request2 = new
                            {
                                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                               
                            };


                            string decryptContent2 = null;
                            string response2 = callNormalApi2(url, request2, ref decryptContent2);
                            using (StreamWriter writer = new StreamWriter("important22.txt"))
                            {

                                writer.WriteLine(response2);
                                writer.Dispose();


                            }

                            var request3 = new
                            {
                                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                                PaymentType = "1",
                                PayID = "11682311000001682"

                            };


                            string decryptContent3 = null;
                            string response3 = callNormalApi3(url, request3, ref decryptContent3);


                            using (StreamWriter writer = new StreamWriter("important33.txt"))
                            {
                                writer.WriteLine(response3);
                                writer.Dispose();

                            }
                      
                        var request4 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankInfoType = "1"

                        };


                        string decryptContent4 = null;
                        string response4 = callNormalApi4(url, request4, ref decryptContent4);


                        using (StreamWriter writer = new StreamWriter("important44.txt"))
                        {
                            writer.WriteLine(response4);
                            writer.Dispose();

                        }

                        var request5 = new
                        {
                            Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                            BankType = "1",
                            BankCode = "007"

                        };


                        string decryptContent5 = null;
                        string response5 = callNormalApi5(url, request5, ref decryptContent5);


                        using (StreamWriter writer = new StreamWriter("important55.txt"))
                        {
                            writer.WriteLine(response5);
                            writer.Dispose();

                        }

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

