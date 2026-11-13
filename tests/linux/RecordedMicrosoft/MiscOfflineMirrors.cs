using System.Collections;
using System.Runtime.Serialization;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

#pragma warning disable SYSLIB0050, SYSLIB0051
internal static class MiscOfflineMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("ExtensionAttributeConstructionComparisonTests.Constructor_preserves_the_same_value", Attributes());
        verify("CompatibilityExceptionSerializationComparisonTests.Exception_metadata_survives_protected_constructor_like_microsoft", ExceptionMetadata());
        verify("DirectoryEntryDisposedWrapperComparisonTests.Property_wrapper_access_after_dispose_matches_microsoft", DisposedWrappers());
    }

    private static List<Sequence> Attributes()
    {
        var rows=new List<Sequence>();
        foreach (var input in new (string Kind,string? Value)[]
        {
            ("property",null),("rdn",null),("class",null),
            ("property",""),("rdn",""),("class",""),
            ("property","description"),("rdn","CN"),("class","user"),
        })
        {
            string? value=null;
            var error=OfflineTheoryMirrors.Capture(() => value=input.Kind switch
            {
                "property" => new AM.DirectoryPropertyAttribute(input.Value!).SchemaAttributeName,
                "rdn" => new AM.DirectoryRdnPrefixAttribute(input.Value!).RdnPrefix,
                _ => new AM.DirectoryObjectClassAttribute(input.Value!).ObjectClass,
            });
            var row=new Sequence();
            row.Observe(47,error?.GetType().FullName,exceptionType:true);
            row.Observe(48,value);
            rows.Add(row);
        }
        return rows;
    }

    private sealed class Operation(SerializationInfo info) : AM.PrincipalOperationException(info,default);
    private sealed class ServerDown(SerializationInfo info) : AM.PrincipalServerDownException(info,default);
    private static SerializationInfo Serialize(Exception error)
    {
        var info=new SerializationInfo(error.GetType(),new FormatterConverter());
        error.GetObjectData(info,default);
        return info;
    }

    private static List<Sequence> ExceptionMetadata()
    {
        var rows=new List<Sequence>();
        foreach (var input in new (bool ServerDown,int Code,string? Server)[]
        {
            (false,1722,null),(false,-2147024891,null),(true,1722,null),
            (true,-2147024891,"dc-東京.example.test"),
        })
        {
            var inner=new InvalidOperationException("original failure");
            Exception source=input.ServerDown
                ? new AM.PrincipalServerDownException("operation failed",inner,input.Code,input.Server!)
                : new AM.PrincipalOperationException("operation failed",inner,input.Code);
            var info=Serialize(source);
            var row=new Sequence();
            void Metadata(SerializationInfo value)
            {
                row.Observe(86,value.GetInt32("errorCode"));
                if (input.ServerDown) row.Observe(87,value.GetString("serverName"));
            }
            Metadata(info);
            Exception result=input.ServerDown ? new ServerDown(info) : new Operation(info);
            row.Observe(68,result.HResult);
            if (!input.ServerDown) row.Observe(72,((AM.PrincipalOperationException)result).ErrorCode);
            var roundTrip=Serialize(result);
            Metadata(roundTrip);
            Metadata(info);
            // The fourth original AssertMetadata call compares clone-only data.
            // It is explicitly excluded from the Microsoft oracle admission.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> DisposedWrappers()
    {
        var rows=new List<Sequence>();
        foreach (var primed in new[] { false,true })
        foreach (var operation in new[] { "collection","names","values","read-only","null-key" })
        {
            using var entry=new DS.DirectoryEntry();
            if (primed) _=entry.Properties;
            entry.Dispose();
            object? value=null;
            var error=OfflineTheoryMirrors.Capture(() => value=operation switch
            {
                "collection" => entry.Properties is not null,
                "names" => entry.Properties.PropertyNames is not null,
                "values" => entry.Properties.Values is not null,
                "read-only" => ((IDictionary)entry.Properties).IsReadOnly,
                _ => entry.Properties[null!],
            });
            var row=new Sequence();
            row.Observe(45,error?.GetType().FullName,exceptionType:true);
            row.Observe(46,(error as ArgumentException)?.ParamName);
            row.Observe(48,value);
            rows.Add(row);
        }
        return rows;
    }
}
#pragma warning restore SYSLIB0050, SYSLIB0051
