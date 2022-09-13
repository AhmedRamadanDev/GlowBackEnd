﻿using System.ComponentModel.DataAnnotations;

namespace FoodHub.Helpers
{
    public class FileHelper
    {
        public static string UploadedFile(IFormFile img, string webRootPath, string hostUrl,string folder)
        {
            string uniqueFileName = null;
            string uploadsFolder = Path.Combine(webRootPath, "images", folder);
            uniqueFileName = Guid.NewGuid().ToString() + "_" + img.FileName;
            string filePath = Path.Combine(uploadsFolder, uniqueFileName);
            Directory.CreateDirectory(uploadsFolder);

            //string final = $"{hostUrl}/images/{uniqueFileName}";
            // TODO: when production
            string final = $"/images/{folder}/{uniqueFileName}";
            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                img.CopyTo(fileStream);
            }

            return final;
        }


        public static void SaveFile(string path, Byte[] file)
        {
            File.WriteAllBytes(path, file);
        }
    }


    public class AllowedExtensionsAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;
        public AllowedExtensionsAttribute(string[] extensions)
        {
            _extensions = extensions;
        }

        protected override ValidationResult IsValid(
        object value, ValidationContext validationContext)
        {
            var file = value as IFormFile;
            if (file != null)
            {
                var extension = Path.GetExtension(file.FileName);
                if (!_extensions.Contains(extension.ToLower()))
                {
                    return new ValidationResult(GetErrorMessage());
                }
            }

            return ValidationResult.Success;
        }

        public string GetErrorMessage()
        {
            return $"امتداد الصورة هذا غير مسموح به!";
        }
    }
}