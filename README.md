# PowerShellScripts

# Private Repo File Fetcher

This is a function that will act as a proxy server allowing you to download or execute artiacts held in a private repo (currenlty GitHub). It takes 2 parameters
<li>githuburi - the original RAW GitHub uri</li>
<li>githubaccessoken - a git hub personal access token</li>

As the function contains not sensative info and to keep the uri short set the function authorisation level to anonymouse

To call the function you should construct a URL as follos:
https://[App name].azurewebsites.net/api/PrivateRepoFileFetcher?githuburi=http://raw.githubusercontent.com/[GitHub Username]/[Repository]/[branch]/[path to the file]&githubaccesstoken=[GitHub Personal Access Token]
