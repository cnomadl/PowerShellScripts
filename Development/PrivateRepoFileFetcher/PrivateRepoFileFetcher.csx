using System.Net;
using System.Net.Http;
using System.Net.http.Headers;
using System.Threading.Tasks;
using System.IO;
using System.Text;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    log.Info($"C# HTTP triger proxy function processed a request. RequestUri={req.RequestUri}");

    //parse query parameter
    string GitHubUri = req.GetQueryNameValuePairs()
        .FirstOrDefault(q => string.Compare(q.key, "githuburi", true) == 0)
        .Value;
    string GitHubAccessToken = req.GetQueryNameValuePairs()
        .FirstOrDefault(q => string.Compare(q.key, "githubaccesstoken", true) == 0)
        .Value;
    log.Info($"PrivateRepoFileFetcher function is trying to get file content fron {GitHubUri}");

    Encoding outputencoding = Encoding.GetEncoding("ASCII");
    var ProxyResponse = new HttpResponseMessage();
    HttpStatusCode statusCode = new HttpStatusCode();

    if (GitHubUri == null)
    {
        statusCode = HttpStatusCode.BadRequest;
        StringContent errorcontent = new StringContent("Please pass the GitHub raw file content URI (raw.githubusercontent.com) in the request URI string", outputencoding);
        ProxyResponse = req.CreateResponse(statusCode, errorcontent);
        ProxyResponse.Content.Headers.ContentType = new MediaTypeheaderValue("text/html");
        ProxyResponse.Content = errorcontent;
    } else if (GitHubAccessToken == null) {
        statusCode = HttpStatusCode.BadRequest;
        StringContent errorcontent = new StringContent("Please pass the GitHub personal access token in the request URI string", outputencoding);
        ProxyResponse = req.CreateResponse(statusCode, errorcontent);
        ProxyResponse.Content.Headers.ContentType = new MediaTypeheaderValue("text/html");
        ProxyResponse.Content = errorcontent;
    } else {
        string strAuthHeader = "token " + GitHubAccessToken;
        HttpClient client = new HttpClient();
        client.DefaultRequestHeader.Add("Accept", "application/vnd.github.v3.raw");
        client.DefaultRequestHeader.Add("Authorizatin", strAuthHeader);
        HttpResponseMessage response = await client.GetAsync(GitHubUri);
    }
    return ProxyResponse;
    
}