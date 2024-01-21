# Overview

This vulnerability was reported by [annfalotaibi](https://huntr.com/users/annfalotaibi)

Source link for the reported vulnerabilities are as follows:
* https://huntr.com/bounties/aed70a15-b1c6-4eae-9e47-02a1dd86ce7c/

[How to Identify Similar vulnerabilities](#how-to-identify-similar-vulnerabilities)

# Path Traversal in UrlMappins.groovy

The problem in this was quite straightforward but to understand it, we will go over two functions, one that is parsing the URL containing a user-controlled parameter which is responsible for referencing files by their `id`. Even though the application is using `id` instead of filename for referencing the files to be shown. Following piece of code maps the URL and parameter for the `textfiles` processing.
```groovy
    "/bigbluebutton/presentation/$conference/$room/$presentation_name/textfiles/$id"(controller: "presentation") {
      action = [GET: 'showTextfile']
```
[UrlMappings.groovy](https://github.com/bigbluebutton/bigbluebutton/blob/adcd139ec061a718a78f02a2432fed9433e271a8/bigbluebutton-web/grails-app/controllers/org/bigbluebutton/web/UrlMappings.groovy)
Now, from the above code you could make the educated guess that it takes parameters like `id`, `presentation_name` etc. and let the `"presentation"` controller's `showTextfile` function to handle processing:

```groovy
def showTextfile = {
    def presentationName = params.presentation_name
    def conf = params.conference
    def rm = params.room
    def textfile = params.id
    log.debug "Controller: Show textfile request for $presentationName $textfile"

    log.error("Nginx should be serving this text file! meetingId=" + conf + ",presId=" + presentationName + ",page=" + textfile);

    InputStream is = null;
    try {
      def pres = presentationService.showTextfile(conf, rm, presentationName, textfile)
      if (pres.exists()) {
        log.debug "Controller: Sending textfiles reply for $presentationName $textfile"

        def bytes = pres.readBytes()
        response.addHeader("Cache-Control", "no-cache")
        response.contentType = 'plain/text'
        response.outputStream << bytes;
      } else {
        log.debug "$pres does not exist."
      }
    } catch (IOException e) {
      log.error("Failed to read text file. meetingId=" + conf + ",presId=" + presentationName + ",page=" + textfile);
      log.error("Error reading text file.\n" + e.getMessage());
    }
  }
```
[PresentationController.groovy](https://github.com/bigbluebutton/bigbluebutton/blob/adcd139ec061a718a78f02a2432fed9433e271a8/bigbluebutton-web/grails-app/controllers/org/bigbluebutton/web/controllers/PresentationController.groovy#L300)


As we can see above that the `showTextfile` function calls another method ` presentationService.showTextfile(conf, rm, presentationName, textfile)` where all of these parameters are directly taken from the `showTextfile` function call, in this case URL parameters that we saw earlier.

Digging into the `presentationService` class, we could see that the `showTextFile` function just returns a `File` object by preparing a filepath from the passed parameters, since the `textfile` parameter is one of the parameters we controlled (in the above function it was referenced as `id` later assigned with variable named `textfile`), what can we do here due to lack of any filter on the `textfile` parameter, any attacker can just point to an existing directory first and then do path traversal attack to read local files, though the problem here is that we are only limited to `txt` extension file.

```groovy
	def showTextfile = {conf, room, presentationName, textfile ->
		def txt = roomDirectory(conf, room).absolutePath + File.separatorChar + presentationName + File.separatorChar +
				"textfiles" + File.separatorChar + "slide-${textfile}.txt"
		log.debug "showing $txt"

		new File(txt)
	}
```
[PresentationService.groovy](https://github.com/bigbluebutton/bigbluebutton/blob/adcd139ec061a718a78f02a2432fed9433e271a8/bigbluebutton-web/grails-app/services/org/bigbluebutton/web/services/PresentationService.groovy#L121)


### Patch

The patch is rather way too simple in this case, groovy allows you to have a specific type of parameter by performing a type check on the input, in this case, the developers deployed a fix where they check `id` parameter to be strictly of integer parameter:

```groovy
    "/bigbluebutton/presentation/$conference/$room/$presentation_name/textfiles/$id"(controller: "presentation") {
      action = [GET: 'showTextfile']
      constraints {
        id matches: /\d+/
      }
    }
```

---

### How to Identify Similar vulnerabilities

As usualy, mapping out the functions which do file based operations can help narrowing down the potential issues that may lead to local file read. Also, checking you might be limited to reading specific extension of a file but that does not mean it is less of a problem for the overall application security. 