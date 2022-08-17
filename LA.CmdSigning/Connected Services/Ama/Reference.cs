﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Ama
{
    using System.Runtime.Serialization;
    
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    [System.Runtime.Serialization.DataContractAttribute(Name="SignRequest", Namespace="http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature")]
    public partial class SignRequest : object
    {
        
        private byte[] ApplicationIdField;
        
        private string DocNameField;
        
        private byte[] HashField;
        
        private string PinField;
        
        private string UserIdField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public byte[] ApplicationId
        {
            get
            {
                return this.ApplicationIdField;
            }
            set
            {
                this.ApplicationIdField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute()]
        public string DocName
        {
            get
            {
                return this.DocNameField;
            }
            set
            {
                this.DocNameField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public byte[] Hash
        {
            get
            {
                return this.HashField;
            }
            set
            {
                this.HashField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string Pin
        {
            get
            {
                return this.PinField;
            }
            set
            {
                this.PinField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string UserId
        {
            get
            {
                return this.UserIdField;
            }
            set
            {
                this.UserIdField = value;
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    [System.Runtime.Serialization.DataContractAttribute(Name="SignStatus", Namespace="http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature")]
    public partial class SignStatus : object
    {
        
        private string CodeField;
        
        private string FieldField;
        
        private string FieldValueField;
        
        private string MessageField;
        
        private string ProcessIdField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string Code
        {
            get
            {
                return this.CodeField;
            }
            set
            {
                this.CodeField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string Field
        {
            get
            {
                return this.FieldField;
            }
            set
            {
                this.FieldField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string FieldValue
        {
            get
            {
                return this.FieldValueField;
            }
            set
            {
                this.FieldValueField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string Message
        {
            get
            {
                return this.MessageField;
            }
            set
            {
                this.MessageField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string ProcessId
        {
            get
            {
                return this.ProcessIdField;
            }
            set
            {
                this.ProcessIdField = value;
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    [System.Runtime.Serialization.DataContractAttribute(Name="SignResponse", Namespace="http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature")]
    public partial class SignResponse : object
    {
        
        private Ama.HashStructure[] ArrayOfHashStructureField;
        
        private byte[] SignatureField;
        
        private Ama.SignStatus StatusField;
        
        private string certificateField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public Ama.HashStructure[] ArrayOfHashStructure
        {
            get
            {
                return this.ArrayOfHashStructureField;
            }
            set
            {
                this.ArrayOfHashStructureField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public byte[] Signature
        {
            get
            {
                return this.SignatureField;
            }
            set
            {
                this.SignatureField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public Ama.SignStatus Status
        {
            get
            {
                return this.StatusField;
            }
            set
            {
                this.StatusField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string certificate
        {
            get
            {
                return this.certificateField;
            }
            set
            {
                this.certificateField = value;
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    [System.Runtime.Serialization.DataContractAttribute(Name="HashStructure", Namespace="http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature")]
    public partial class HashStructure : object
    {
        
        private byte[] HashField;
        
        private string NameField;
        
        private string idField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public byte[] Hash
        {
            get
            {
                return this.HashField;
            }
            set
            {
                this.HashField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string Name
        {
            get
            {
                return this.NameField;
            }
            set
            {
                this.NameField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    [System.Runtime.Serialization.DataContractAttribute(Name="MultipleSignRequest", Namespace="http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature")]
    public partial class MultipleSignRequest : object
    {
        
        private byte[] ApplicationIdField;
        
        private string PinField;
        
        private string UserIdField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public byte[] ApplicationId
        {
            get
            {
                return this.ApplicationIdField;
            }
            set
            {
                this.ApplicationIdField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string Pin
        {
            get
            {
                return this.PinField;
            }
            set
            {
                this.PinField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string UserId
        {
            get
            {
                return this.UserIdField;
            }
            set
            {
                this.UserIdField = value;
            }
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://Ama.Authentication.Service/", ConfigurationName="Ama.SCMDService")]
    public interface SCMDService
    {
        
        [System.ServiceModel.OperationContractAttribute(Action="http://Ama.Authentication.Service/SCMDService/SCMDSign", ReplyAction="http://Ama.Authentication.Service/SCMDService/SCMDSignResponse")]
        System.Threading.Tasks.Task<Ama.SignStatus> SCMDSignAsync(Ama.SignRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://Ama.Authentication.Service/SCMDService/GetCertificate", ReplyAction="http://Ama.Authentication.Service/SCMDService/GetCertificateResponse")]
        System.Threading.Tasks.Task<string> GetCertificateAsync(byte[] applicationId, string userId);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://Ama.Authentication.Service/SCMDService/GetCertificateWithPin", ReplyAction="http://Ama.Authentication.Service/SCMDService/GetCertificateWithPinResponse")]
        System.Threading.Tasks.Task<Ama.SignStatus> GetCertificateWithPinAsync(byte[] applicationId, string userId, string pin);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://Ama.Authentication.Service/SCMDService/ValidateOtp", ReplyAction="http://Ama.Authentication.Service/SCMDService/ValidateOtpResponse")]
        System.Threading.Tasks.Task<Ama.SignResponse> ValidateOtpAsync(string code, string processId, byte[] applicationId);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://Ama.Authentication.Service/SCMDService/SCMDMultipleSign", ReplyAction="http://Ama.Authentication.Service/SCMDService/SCMDMultipleSignResponse")]
        System.Threading.Tasks.Task<Ama.SignStatus> SCMDMultipleSignAsync(Ama.MultipleSignRequest request, Ama.HashStructure[] documents);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://Ama.Authentication.Service/SCMDService/ForceSMS", ReplyAction="http://Ama.Authentication.Service/SCMDService/ForceSMSResponse")]
        System.Threading.Tasks.Task<Ama.SignStatus> ForceSMSAsync(string processId, string citizenId, byte[] applicationId);
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    public interface SCMDServiceChannel : Ama.SCMDService, System.ServiceModel.IClientChannel
    {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.2")]
    public partial class SCMDServiceClient : System.ServiceModel.ClientBase<Ama.SCMDService>, Ama.SCMDService
    {
        
        /// <summary>
        /// Implement this partial method to configure the service endpoint.
        /// </summary>
        /// <param name="serviceEndpoint">The endpoint to configure</param>
        /// <param name="clientCredentials">The client credentials</param>
        static partial void ConfigureEndpoint(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Description.ClientCredentials clientCredentials);
        
        public SCMDServiceClient() : 
                base(SCMDServiceClient.GetDefaultBinding(), SCMDServiceClient.GetDefaultEndpointAddress())
        {
            this.Endpoint.Name = EndpointConfiguration.BasicHttpBinding_SCMDService.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public SCMDServiceClient(EndpointConfiguration endpointConfiguration) : 
                base(SCMDServiceClient.GetBindingForEndpoint(endpointConfiguration), SCMDServiceClient.GetEndpointAddress(endpointConfiguration))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public SCMDServiceClient(EndpointConfiguration endpointConfiguration, string remoteAddress) : 
                base(SCMDServiceClient.GetBindingForEndpoint(endpointConfiguration), new System.ServiceModel.EndpointAddress(remoteAddress))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public SCMDServiceClient(EndpointConfiguration endpointConfiguration, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(SCMDServiceClient.GetBindingForEndpoint(endpointConfiguration), remoteAddress)
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public SCMDServiceClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress)
        {
        }
        
        public System.Threading.Tasks.Task<Ama.SignStatus> SCMDSignAsync(Ama.SignRequest request)
        {
            return base.Channel.SCMDSignAsync(request);
        }
        
        public System.Threading.Tasks.Task<string> GetCertificateAsync(byte[] applicationId, string userId)
        {
            return base.Channel.GetCertificateAsync(applicationId, userId);
        }
        
        public System.Threading.Tasks.Task<Ama.SignStatus> GetCertificateWithPinAsync(byte[] applicationId, string userId, string pin)
        {
            return base.Channel.GetCertificateWithPinAsync(applicationId, userId, pin);
        }
        
        public System.Threading.Tasks.Task<Ama.SignResponse> ValidateOtpAsync(string code, string processId, byte[] applicationId)
        {
            return base.Channel.ValidateOtpAsync(code, processId, applicationId);
        }
        
        public System.Threading.Tasks.Task<Ama.SignStatus> SCMDMultipleSignAsync(Ama.MultipleSignRequest request, Ama.HashStructure[] documents)
        {
            return base.Channel.SCMDMultipleSignAsync(request, documents);
        }
        
        public System.Threading.Tasks.Task<Ama.SignStatus> ForceSMSAsync(string processId, string citizenId, byte[] applicationId)
        {
            return base.Channel.ForceSMSAsync(processId, citizenId, applicationId);
        }
        
        public virtual System.Threading.Tasks.Task OpenAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginOpen(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndOpen));
        }
        
        public virtual System.Threading.Tasks.Task CloseAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginClose(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndClose));
        }
        
        private static System.ServiceModel.Channels.Binding GetBindingForEndpoint(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.BasicHttpBinding_SCMDService))
            {
                System.ServiceModel.BasicHttpsBinding result = new System.ServiceModel.BasicHttpsBinding();
                result.MaxBufferSize = int.MaxValue;
                result.ReaderQuotas = System.Xml.XmlDictionaryReaderQuotas.Max;
                result.MaxReceivedMessageSize = int.MaxValue;
                result.AllowCookies = true;
                result.Security.Mode = System.ServiceModel.BasicHttpsSecurityMode.Transport;
                return result;
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.EndpointAddress GetEndpointAddress(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.BasicHttpBinding_SCMDService))
            {
                return new System.ServiceModel.EndpointAddress("https://replace_with_url_from_config_settings");
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.Channels.Binding GetDefaultBinding()
        {
            return SCMDServiceClient.GetBindingForEndpoint(EndpointConfiguration.BasicHttpBinding_SCMDService);
        }
        
        private static System.ServiceModel.EndpointAddress GetDefaultEndpointAddress()
        {
            return SCMDServiceClient.GetEndpointAddress(EndpointConfiguration.BasicHttpBinding_SCMDService);
        }
        
        public enum EndpointConfiguration
        {
            
            BasicHttpBinding_SCMDService,
        }
    }
}
