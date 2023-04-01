# WordPress Enumeration Techniques

If you are testing the security of WordPress websites, you will likely have to look at the REST endpoints. By default, users can be listed with the route “/wp-json/wp/v2/users”. On the latest WordPress version, out of the box, you will get the username and the hashed email. Experienced WordPress administrators and users are aware of the potential disclosure. Therefore, we can see [various](https://www.wpbeginner.com/wp-tutorials/how-to-disable-json-rest-api-in-wordpress/) [tutorials](https://neliosoftware.com/blog/protect-your-wordpress-by-hiding-the-rest-api/) [online](https://perishablepress.com/stop-user-enumeration-wordpress/) on how to hide this

![6 ways to enumerate WordPress Users](https://gosecure.wpenginepowered.com/wp-content/uploads/wordpress-bypass\_crop.png)

information. The recommended ways are either to disable the REST API completely, install a security plugin which disables the specific route or block specific request paths.

After evaluating hundreds of websites, we can say that rare are the sites that have totally blocked the feature.

![6 ways to enumerate WordPress Users](https://gosecure.wpenginepowered.com/wp-content/uploads/wordpress-bypass\_crop.png)

If you are testing the security of WordPress websites, you will likely have to look at the REST endpoints. By default, users can be listed with the route “/wp-json/wp/v2/users”. On the latest WordPress version, out of the box, you will get the username and the hashed email. Experienced WordPress administrators and users are aware of the potential disclosure. Therefore, we can see [various](https://www.wpbeginner.com/wp-tutorials/how-to-disable-json-rest-api-in-wordpress/) [tutorials](https://neliosoftware.com/blog/protect-your-wordpress-by-hiding-the-rest-api/) [online](https://perishablepress.com/stop-user-enumeration-wordpress/) on how to hide this information. The recommended ways are either to disable the REST API completely, install a security plugin which disables the specific route or block specific request paths.

After evaluating hundreds of websites, we can say that rare are the sites that have totally blocked the feature.

### 1. HTTP parameter “rest\_route”

The first bypass we are presenting is abusing an alternative path to reach the same endpoint. While Worpdress is configured – by default – to support URL rewriting to have search engine and human friendly URLs like `https://website.com/2020/12/breaking-news` instead of `https://website.com/?p=2678`, behind the scene, every request sent to /wp-json/ is entering the index page with the parameter “rest\_route” set to /wp/v2/users.

| https://\*\*\*\*.com/blog/wp-json/wp/v2/users       | BLOCKED |
| --------------------------------------------------- | ------- |
| https://\*\*\*\*.com/blog/?rest\_route=/wp/v2/users | OK      |

### 2. WordPress.com API

The second method has already been described on the previous blog post on Jetpack emails public disclosure. While you may have a security plugin such as iThemes security, it does not mean that another plugin will not spoil the information elsewhere. In the case of the Jetpack plugin, data including the users’ list is exported to wordpress.com and made available through a public REST API.

| https://blog.\*\*\*\*\*\*\*.com/wp-json/wp/v2/users                            | BLOCKED |
| ------------------------------------------------------------------------------ | ------- |
| https://public-api.wordpress.com/rest/v1.1/sites/blog.\*\*\*\*\*\*\*.com/posts | OK      |

### 3. One by one

There are multiples route that are pointing to the users’ resources. The following PHP code will disable the route that list all users (“wp/v2/users”).

```
add_filter( 'rest_endpoints', function( $endpoints ){
    if ( isset( $endpoints['/wp/v2/users'] ) ) {
        unset( $endpoints['/wp/v2/users'] );
    }    return $endpoints;
});
```

However, there is a second endpoint that can be forgotten: “/wp/v2/users/(?P

\[\d]+)”, a resource that gets the user’s details by id.

In the table below, we can see that one host was refusing to serve the complete list of users. However, we realize that targeting a specific user was not being blocked.

| https://www.\*\*\*\*\*.org/wp-json/wp/v2/users   | BLOCKED |
| ------------------------------------------------ | ------- |
| https://www.\*\*\*\*\*.org/wp-json/wp/v2/users/1 | OK      |

Another potential reason, it that some cloud providers have put in place Web Application Firewall (WAF) to filter traffic for all their managed WordPress hosting. These firewalls will block specific paths. Being decoupled from the application, firewalls have a challenging task: maximize the coverage of malicious requests and reduce the false positives.

### 4. Case sensitivity

In a REST request, the route is used to define the resource selected. Keep in mind that WordPress is modular. The resources (or services) will depend based on the plugins installed and the WordPress configuration. The parameter rest\_route is matched against the list of routes provided by all handlers. The match is done using a case insensitive regular expression.

```
foreach ( $routes as $route => $handlers ) {
    $match = preg_match( '@^' . $route . '$@i', $path, $matches );

    if ( ! $match ) {
        continue;
    }

    $args = array();
```

For this reason, a valid WAF rule would need to be case insensitive as well.

```
RewriteCond %{QUERY_STRING} \bwp/v2/users\b [NC]
RewriteRule ^ - [F]
```

It is easy to add WAF rule and forget to enable insensitivity.

```
RewriteCond %{QUERY_STRING} \bwp/v2/users\b
```

In the following example, we saw a website where there appears to have a filter like the previous case sensitive Apache rule. We can see that the usual REST route was blocked but updating the path with one uppercase character or more would fool the rewrite rule.

| https://blog.\*\*\*\*\*.com/section/news?rest\_route=/wp/v2/users | BLOCKED |
| ----------------------------------------------------------------- | ------- |
| https://blog.\*\*\*\*\*.com/section/news?rest\_route=/wp/v2/usErs | OK      |

### 5. Search

On few occasions we encounter APIs that are not explicitly blocked but the [/wp/v2/users endpoint](https://developer.wordpress.org/rest-api/reference/users/) is not returning the [avatar\_urls](https://developer.wordpress.org/rest-api/reference/users/) properties. This is the effect of a third-party security plugin or disabling manually the avatars (Settings > Discussion > Avatars).

![wordpress-bypass\_image-1](https://gosecure.wpenginepowered.com/wp-content/uploads/wordpress-bypass\_image-1.png)

Setting that will hide avatars both in web pages and REST response

We did find a workaround for those as well. The endpoint supports the parameter “search”. Its value is match against all user’s fields including the email address. With simple automation it is possible to discover each email address. The user information associated to an email matched will be returned in the JSON response. From experience, we can estimate that between 200 and 400 requests will be required to reveal one email address.

| https://api.\*\*\*\*\*.com/wp-json/wp/v2/users                                                                                                                                                                                                                                                                                                          | BLOCKED |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| <p>https://api.*****.com/wp-json/wp/v2/users?search=r@initech.com<br>https://api.*****.com/wp-json/wp/v2/users?search=er@initech.com<br>https://api.*****.com/wp-json/wp/v2/users?search=ter@initech.com<br>https://api.*****.com/wp-json/wp/v2/users?search=eter@initech.com<br>https://api.*****.com/wp-json/wp/v2/users?search=peter@initech.com</p> | OK      |

### 6. Yoast SEO

Yoast SEO is a WordPress plugin that helps blog authors preview how the blog will be displayed in search engines along with some help to complete key website metadata. When the plugin is installed, metadata in the form of a JSON message is included in every page. Metadata about the post’s author is also included which will return its gravatar URL.

```
<script type='application/ld+json' class='yoast-schema-graph yoast-schema-graph--main'>{"@context":"https://schema.org","@graph":[{"@type":"WebSite","@id":"https:// ***** /#website","url":"https://www.******.com/","name":"*****",
[...]
},

{
"@type":["Person"],
"@id":"https://www.****.com/#/schema/person/7367999b66**********",
"name":"Fred",
"image":{
"@type":"ImageObject",
"@id":"https://www.******.com/#authorlogo",
"url":"https://secure.gravatar.com/avatar/de04459893a29***********?s=96&d=mm&r=g",
"caption":"****"
},
"sameAs":[]
}]
</script>
```

Example of Yoast JSON metadata

### Conclusion

The default behavior of exposing usernames and emails from blog authors is unlikely to change soon. It is a risk that has been accepted by the WordPress team. We hope that the earlier list will help privacy cautious administrators to assess properly their hardening configuration.

_Clients of GoSecure Managed Detection and Response (MDR) with the Network Detection and Response have detection capabilities in-place in case of WordPress user enumeration and other malicious requests sent to WordPress._
