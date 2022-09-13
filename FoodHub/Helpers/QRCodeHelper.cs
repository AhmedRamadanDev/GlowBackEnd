using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using Microsoft.AspNetCore.Hosting;

using ZXing.Common;
using ZXing;
using ZXing.QrCode;
using ZXing.Windows.Compatibility;

namespace AdminLTE.MVC.Helpers
{
    public static class QrCodeHelper
    {

        public static string GenerateQrCode(
            string userName, DateTime CreateDateTime, string Role,
            string Email, IWebHostEnvironment webHostEnvironment
            )
        {
            string uniqueFileName = Guid.NewGuid().ToString() + ".jpeg";
            string uploadsFolder = Path.Combine(webHostEnvironment.WebRootPath, "QrCodes");
            string filePath = Path.Combine(uploadsFolder, uniqueFileName);
            string final = uniqueFileName;
            Directory.CreateDirectory(uploadsFolder);
            string qrString = "1) UserName : " + userName + "\n" + "\n" + "\n"
                            + "2) Date created : " + CreateDateTime.ToString() + "\n" + "\n" + "\n"
                            + "3) Role : " + Role + " \n" + "\n" + "\n"
                            + "4) Email : " + Email + "\n" + "\n" + "\n"
                            ;

            //QRCodeGenerator qrGenerator = new QRCodeGenerator();
            //QRCodeData qrCodeData = qrGenerator.CreateQrCode(qrString, QRCodeGenerator.ECCLevel.Q, true);
            //QRCode qrCode = new QRCode(qrCodeData);
            //Bitmap qrCodeImage = qrCode.GetGraphic(20);
            //qrCodeImage.Save(filePath, ImageFormat.Png);
            //return final;

            QrCodeEncodingOptions options = new QrCodeEncodingOptions();
            options = new QrCodeEncodingOptions
            {
                DisableECI = false,
                CharacterSet = "UTF-8",
                Width = 300,
                Height = 300,
            };
            var writer = new BarcodeWriter()
            {
                Format = BarcodeFormat.QR_CODE,
                Options = options
            };
            var result = writer.Write(qrString.Trim());
            result.Save(filePath, ImageFormat.Png);
            return final;
        }
    }
}