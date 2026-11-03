## 请求头顺序表

| 编号 | HTTP/3.0                  | HTTP/2.0                    | HTTP/1.1                  |
|:-----|:--------------------------|:----------------------------|:--------------------------|
| 1    | :method                   | :method                     | Host                      |
| 2    | :authority                | :authority                  | Connection                |
| 3    | :scheme                   | :scheme                     | Content-Length            |
| 4    | :path                     | :path                       | Authorization             |
| 5    | origin                    | cache-control               | Content-Type              |
| 6    | sec-ch-ua-arch            | sec-ch-ua                   | Cache-Control             |
| 7    | sec-ch-ua-platform        | sec-ch-ua-mobile            | sec-ch-ua                 |
| 8    | upgrade-insecure-requests | sec-ch-ua-full-version      | sec-ch-ua-mobile          |
| 9    | user-agent                | sec-ch-ua-arch              | sec-ch-ua-platform        |
| 10   | sec-ch-ua                 | sec-ch-ua-platform          | Upgrade-Insecure-Requests |
| 11   | sec-ch-ua-wow64           | sec-ch-ua-platform-version  | User-Agent                |
| 12   | sec-ch-ua-mobile          | sec-ch-ua-model             | Accept                    |
| 13   | accept                    | sec-ch-ua-bitness           | Sec-Fetch-Site            |
| 14   | sec-fetch-site            | sec-ch-ua-full-version-list | Sec-Fetch-Mode            |
| 15   | sec-fetch-mode            | upgrade-insecure-requests   | Sec-Fetch-User            |
| 16   | sec-fetch-user            | user-agent                  | Sec-Fetch-Dest            |
| 17   | sec-fetch-dest            | accept                      | Sec-Fetch-Storage-Access  |
| 18   | referer                   | origin                      | Referer                   |
| 19   | accept-encoding           | sec-fetch-site              | Accept-Encoding           |
| 20   | accept-language           | sec-fetch-mode              | Accept-Language           |
| 21   | cookie                    | sec-fetch-user              | Cookie                    |
| 22   | priority                  | sec-fetch-dest              | Origin                    |
| 23   |                           | sec-fetch-storage-access    |                           |
| 24   |                           | referer                     |                           |
| 25   |                           | accept-encoding             |                           |
| 26   |                           | accept-language             |                           |
| 27   |                           | cookie                      |                           |
| 28   |                           | priority                    |                           |






