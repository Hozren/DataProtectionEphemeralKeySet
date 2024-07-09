// write cert to DB
public void SetStringValue(string name, string data)
{
    var param = ReadEntityContext.Find(name);
    if (param == null)
    {
        param = new GlobalParams { Name = name, Value = data };
        WriteContext.Add(param);
    }
    else
    {
        param.Value = data;
        WriteContext.Update(param);
    }

    WriteContext.SaveChanges();
    WriteContext.Detach(param);
}

// write cert to db as base64-string (data - cert as file)
public void SetInternalX509CookieCert(byte[] data, string password)
{
    SetStringValue(COOKIE_X509_CERT, Convert.ToBase64String(data));
    SetStringValue(COOKIE_X509_CERT_PASSWD, password);
}

// convert cert as base64-string 
public X509Certificate2 GetInternalX509CookieCert()
{
    var certData = Convert.FromBase64String(GetValue(COOKIE_X509_CERT));
    var certPassword = GetValue(COOKIE_X509_CERT_PASSWD);
    
    //Решение для запуска на MacOS
    var x509KeyStorageFlags = X509KeyStorageFlags.EphemeralKeySet;
    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
    {
        x509KeyStorageFlags = X509KeyStorageFlags.DefaultKeySet;
    }
    
    var cert = new X509Certificate2(certData, certPassword, x509KeyStorageFlags);

    return cert;
}


// configure services in Startup.cs 
public static IServiceCollection AddNsysSharedX509CookieProtection(this IServiceCollection services)
{
    try
    {
        var built = services.BuildServiceProvider();
        var repoFacade = built.GetRequiredService<CoreRepositoriesFacade>();
        var dbCert = repoFacade.GlobalParamsRepository.GetInternalX509CookieCert();

        services.AddDataProtection()
            .AddKeyManagementOptions(options => options.XmlRepository = built.GetService<IXmlRepository>())
            .SetApplicationName(APPLICATION_NAME)
            .ProtectKeysWithCertificate(dbCert);
        return services;
    }
    catch (Exception ex)
    {
        Console.WriteLine("Could not set up DataProtection");
        Console.WriteLine(ex.StackTrace);
        throw;
    }
}
