## request header order

| No. | HTTP/3.0                  | HTTP/2.0                    | HTTP/1.1                  |
|:-----|:--------------------------|:----------------------------|:--------------------------|
| 1    | :method                   | :method                     | Host                      |
| 2    | :authority                | :authority                  | Connection                |
| 3    | :scheme                   | :scheme                     | Content-Length            |
| 4    | :path                     | :path                       | Authorization             |
| 5    | origin                    | pragma                      | Content-Type              |
| 6    | sec-ch-ua-arch            | cache-control               | Cache-Control             |
| 7    | sec-ch-ua-platform        | ect                         | sec-ch-ua                 |
| 8    | upgrade-insecure-requests | sec-ch-ua                   | sec-ch-ua-mobile          |
| 9    | user-agent                | sec-ch-ua-mobile            | sec-ch-ua-platform        |
| 10   | sec-ch-ua                 | sec-ch-ua-full-version      | Upgrade-Insecure-Requests |
| 11   | sec-ch-ua-wow64           | sec-ch-ua-arch              | User-Agent                |
| 12   | sec-ch-ua-mobile          | sec-ch-ua-platform          | Accept                    |
| 13   | accept                    | sec-ch-ua-platform-version  | Sec-Fetch-Site            |
| 14   | sec-fetch-site            | sec-ch-ua-model             | Sec-Fetch-Mode            |
| 15   | sec-fetch-mode            | sec-ch-ua-bitness           | Sec-Fetch-User            |
| 16   | sec-fetch-user            | sec-ch-ua-full-version-list | Sec-Fetch-Dest            |
| 17   | sec-fetch-dest            | sec-ch-prefers-color-scheme | Sec-Fetch-Storage-Access  |
| 18   | referer                   | upgrade-insecure-requests   | Referer                   |
| 19   | accept-encoding           | content-type                | Accept-Encoding           |
| 20   | accept-language           | user-agent                  | Accept-Language           |
| 21   | cookie                    | accept                      | Cookie                    |
| 22   | priority                  | origin                      | Origin                    |
| 23   | cache-control             | sec-fetch-site              |                           |
| 24   | sec-ch-ua-full-version    | sec-fetch-mode              |                           |
| 25   | sec-ch-ua-platform-version| sec-fetch-user              |                           |
| 26   | sec-ch-ua-model           | sec-fetch-dest              |                           |
| 27   | sec-ch-ua-bitness         | sec-fetch-storage-access    |                           |
| 28   | sec-ch-ua-full-version-list| referer                    |                           |
| 29   | sec-fetch-storage-access  | accept-encoding             |                           |
| 30   | content-encoding          | accept-language             |                           |
| 31   | content-type              | cookie                      |                           |
| 32   | authorization             | priority                    |                           |
| 33   |                           | content-encoding            |                           |
| 34   |                           | authorization               |                           |







