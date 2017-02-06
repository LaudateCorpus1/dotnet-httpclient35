//
// HttpClientHandler.cs
//
// Authors:
//	Marek Safar  <marek.safar@gmail.com>
//
// Copyright (C) 2011 Xamarin Inc (http://www.xamarin.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Specialized;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Linq;
using Rackspace.Threading;

namespace System.Net.Http
{
	public class HttpClientHandler : HttpMessageHandler
	{
		static long groupCounter;

		bool allowAutoRedirect;
		DecompressionMethods automaticDecompression;
		CookieContainer cookieContainer;
		ICredentials credentials;
		int maxAutomaticRedirections;
		long maxRequestContentBufferSize;
		bool preAuthenticate;
		IWebProxy proxy;
		bool useCookies;
		bool useDefaultCredentials;
		bool useProxy;
		ClientCertificateOption certificate;
		int sentRequest;
        HttpWebRequest wrequest;
        string connectionGroupName;
		int disposed;

		public HttpClientHandler ()
		{
			allowAutoRedirect = true;
			maxAutomaticRedirections = 50;
			maxRequestContentBufferSize = int.MaxValue;
			useCookies = true;
			useProxy = true;
			connectionGroupName = "HttpClientHandler" + Interlocked.Increment (ref groupCounter);
		}

		internal void EnsureModifiability ()
		{
			if (sentRequest != 0)
				throw new InvalidOperationException (
					"This instance has already started one or more requests. " +
					"Properties can only be modified before sending the first request.");
		}

		public bool AllowAutoRedirect {
			get {
				return allowAutoRedirect;
			}
			set {
				EnsureModifiability ();
				allowAutoRedirect = value;
			}
		}

		public DecompressionMethods AutomaticDecompression {
			get {
				return automaticDecompression;
			}
			set {
				EnsureModifiability ();
				automaticDecompression = value;
			}
		}

		public ClientCertificateOption ClientCertificateOptions {
			get {
				return certificate;
			}
			set {
				EnsureModifiability ();
				certificate = value;
			}
		}

		public CookieContainer CookieContainer {
			get {
				return cookieContainer ?? (cookieContainer = new CookieContainer ());
			}
			set {
				EnsureModifiability ();
				cookieContainer = value;
			}
		}

		public ICredentials Credentials {
			get {
				return credentials;
			}
			set {
				EnsureModifiability ();
				credentials = value;
			}
		}

		public int MaxAutomaticRedirections {
			get {
				return maxAutomaticRedirections;
			}
			set {
				EnsureModifiability ();
				if (value <= 0)
					throw new ArgumentOutOfRangeException ();

				maxAutomaticRedirections = value;
			}
		}

		public long MaxRequestContentBufferSize {
			get {
				return maxRequestContentBufferSize;
			}
			set {
				EnsureModifiability ();
				if (value < 0)
					throw new ArgumentOutOfRangeException ();

				maxRequestContentBufferSize = value;
			}
		}

		public bool PreAuthenticate {
			get {
				return preAuthenticate;
			}
			set {
				EnsureModifiability ();
				preAuthenticate = value;
			}
		}

		public IWebProxy Proxy {
			get {
				return proxy;
			}
			set {
				EnsureModifiability ();
				if (!UseProxy)
					throw new InvalidOperationException ();

				proxy = value;
			}
		}

		public virtual bool SupportsAutomaticDecompression {
			get {
				return true;
			}
		}

		public virtual bool SupportsProxy {
			get {
				return true;
			}
		}

		public virtual bool SupportsRedirectConfiguration {
			get {
				return true;
			}
		}

		public bool UseCookies {
			get {
				return useCookies;
			}
			set {
				EnsureModifiability ();
				useCookies = value;
			}
		}

		public bool UseDefaultCredentials {
			get {
				return useDefaultCredentials;
			}
			set {
				EnsureModifiability ();
				useDefaultCredentials = value;
			}
		}

		public bool UseProxy {
			get {
				return useProxy;
			}
			set {
				EnsureModifiability ();
				useProxy = value;
			}
		}

		protected override void Dispose (bool disposing)
		{
			if (disposing && disposed == 0) {
                Interlocked.Exchange(ref disposed, 1);
                if (wrequest != null)
                {
                    wrequest.ServicePoint.CloseConnectionGroup(wrequest.ConnectionGroupName);
                    Interlocked.Exchange(ref wrequest, null);
                }
			}

			base.Dispose (disposing);
		}

		internal virtual HttpWebRequest CreateWebRequest (HttpRequestMessage request)
		{
            var wr = (HttpWebRequest)WebRequest.Create(request.RequestUri);
            //wr.ThrowOnError = false;
			wr.AllowWriteStreamBuffering = false;

			wr.ConnectionGroupName = connectionGroupName;
			wr.Method = request.Method.Method;
			wr.ProtocolVersion = request.Version;

			if (wr.ProtocolVersion == HttpVersion.Version10) {
				wr.KeepAlive = request.Headers.ConnectionKeepAlive;
			} else {
				wr.KeepAlive = request.Headers.ConnectionClose != true;
			}

			if (allowAutoRedirect) {
				wr.AllowAutoRedirect = true;
				wr.MaximumAutomaticRedirections = maxAutomaticRedirections;
			} else {
				wr.AllowAutoRedirect = false;
			}

			wr.AutomaticDecompression = automaticDecompression;
			wr.PreAuthenticate = preAuthenticate;

			if (useCookies) {
				// It cannot be null or allowAutoRedirect won't work
				wr.CookieContainer = CookieContainer;
			}

			if (useDefaultCredentials) {
				wr.UseDefaultCredentials = true;
			} else {
				wr.Credentials = credentials;
			}

			if (useProxy) {
				wr.Proxy = proxy;
			} else {
				// Disables default WebRequest.DefaultWebProxy value
				wr.Proxy = null;
			}

			wr.ServicePoint.Expect100Continue = request.Headers.ExpectContinue == true;

			// Add request headers
			AddRequestHeaders(wr, request.Headers);

			
			return wr;
		}

		HttpResponseMessage CreateResponseMessage (HttpWebResponse wr, HttpRequestMessage requestMessage, CancellationToken cancellationToken)
		{
			var response = new HttpResponseMessage (wr.StatusCode);
			response.RequestMessage = requestMessage;
			response.ReasonPhrase = wr.StatusDescription;
			response.Content = new StreamContent (wr.GetResponseStream (), cancellationToken);

			var headers = wr.Headers;
			for (int i = 0; i < headers.Count; ++i) {
				var key = headers.GetKey(i);
				var value = headers.GetValues (i);

				HttpHeaders item_headers;
				if (HttpHeaders.GetKnownHeaderKind (key) == Headers.HttpHeaderKind.Content)
					item_headers = response.Content.Headers;
				else
					item_headers = response.Headers;
					
				item_headers.TryAddWithoutValidation (key, value);
			}

			requestMessage.RequestUri = wr.ResponseUri;

			return response;
		}

		protected async internal override Task<HttpResponseMessage> SendAsync (HttpRequestMessage request, CancellationToken cancellationToken)
		{
			if (disposed != 0)
				throw new ObjectDisposedException (GetType ().ToString ());

            Interlocked.Exchange(ref sentRequest, 1);
            wrequest = CreateWebRequest (request);
			HttpWebResponse wresponse = null;

			try {
				using (cancellationToken.Register (l => ((HttpWebRequest)l).Abort (), wrequest)) {
					var content = request.Content;
					if (content != null) {
                        AddContentHeaders(wrequest, request.Content.Headers);

                        //
                        // Content length has to be set because HttpWebRequest is running without buffering
                        //
                        var contentLength = content.Headers.ContentLength;
						if (contentLength != null) {
							wrequest.ContentLength = contentLength.Value;
						} else {
							await content.LoadIntoBufferAsync (MaxRequestContentBufferSize).ConfigureAwait (false);
							wrequest.ContentLength = content.Headers.ContentLength.Value;
						}

						//wrequest.ResendContentFactory = content.CopyTo;

						var stream = await wrequest.GetRequestStreamAsync ().ConfigureAwait (false);
						await request.Content.CopyToAsync (stream).ConfigureAwait (false);
					} else if (HttpMethod.Post.Equals (request.Method) || HttpMethod.Put.Equals (request.Method) || HttpMethod.Delete.Equals (request.Method)) {
						// Explicitly set this to make sure we're sending a "Content-Length: 0" header.
						// This fixes the issue that's been reported on the forums:
						// http://forums.xamarin.com/discussion/17770/length-required-error-in-http-post-since-latest-release
						wrequest.ContentLength = 0;
					}

					wresponse = (HttpWebResponse)await wrequest.GetResponseAsync ().ConfigureAwait (false);
				}
			} catch (WebException we) {
				if (we.Status != WebExceptionStatus.RequestCanceled)
					throw new HttpRequestException ("An error occurred while sending the request", we);
			} catch (System.IO.IOException ex) {
				throw new HttpRequestException ("An error occurred while sending the request", ex);
			}

			if (cancellationToken.IsCancellationRequested) {
				var cancelled = new TaskCompletionSource<HttpResponseMessage> ();
				cancelled.SetCanceled ();
				return await cancelled.Task;
			}
			
			return CreateResponseMessage (wresponse, request, cancellationToken);
		}

        private static void AddRequestHeaders(HttpWebRequest request, HttpRequestHeaders headers)
        {
            foreach (var header in headers)
            {
                switch (header.Key.ToLowerInvariant())
                {
                    case "accept":
                        request.Accept = headers.Accept.ToString();
                        break;

                    case "connection":
                        request.Connection = headers.Connection.ToString();
                        break;

                    case "date":
                        // .NET 3.5 does not expose a property for setting this reserved header
                        goto default;

                    case "expect":
                        request.Expect = headers.Expect.ToString();
                        break;

                    case "host":
                        // .NET 3.5 does not expose a property for setting this reserved header
                        goto default;

                    case "if-modified-since":
                        request.IfModifiedSince = headers.IfModifiedSince.Value.UtcDateTime;
                        break;

                    case "range":
                        foreach (var range in headers.Range.Ranges)
                        {
                            checked
                            {
                                if (!string.IsNullOrEmpty(headers.Range.Unit))
                                {
                                    if (range.To.HasValue)
                                        request.AddRange(headers.Range.Unit, (int)range.From.Value, (int)range.To.Value);
                                    else
                                        request.AddRange(headers.Range.Unit, (int)range.From.Value);
                                }
                                else
                                {
                                    if (range.To.HasValue)
                                        request.AddRange((int)range.From.Value, (int)range.To.Value);
                                    else
                                        request.AddRange((int)range.From.Value);
                                }
                            }
                        }

                        break;

                    case "referer":
                        request.Referer = headers.Referrer.OriginalString;
                        break;

                    case "transfer-encoding":
                        request.TransferEncoding = headers.TransferEncoding.ToString();
                        break;

                    case "user-agent":
                        request.UserAgent = headers.UserAgent.ToString();
                        break;

                    default:
                        foreach (var value in header.Value)
                        {
                            request.Headers.Add(header.Key, value);
                        }

                        break;
                }
            }
        }

        private static void AddContentHeaders(HttpWebRequest request, HttpContentHeaders headers)
        {
            foreach (var header in headers)
            {
                switch (header.Key.ToLowerInvariant())
                {
                    case "content-length":
                        request.ContentLength = headers.ContentLength.Value;
                        break;

                    case "content-type":
                        request.ContentType = headers.ContentType.ToString();
                        break;

                    default:
                        foreach (var value in header.Value)
                        {
                            request.Headers.Add(header.Key, value);
                        }

                        break;
                }
            }
        }

#if NETSTANDARD
		public bool CheckCertificateRevocationList {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		public X509CertificateCollection ClientCertificates {
			get {
				throw new NotImplementedException ();
			}
		}

		public ICredentials DefaultProxyCredentials {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		public int MaxConnectionsPerServer {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		public int MaxResponseHeadersLength {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		public IDictionary<string,object> Properties {
			get {
				throw new NotImplementedException ();
			}
		}

		public Func<HttpRequestMessage,X509Certificate2,X509Chain,SslPolicyErrors,bool> ServerCertificateCustomValidationCallback {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

		public SslProtocols SslProtocols {
			get {
				throw new NotImplementedException ();
			}
			set {
				throw new NotImplementedException ();
			}
		}

#endif
    }
}
