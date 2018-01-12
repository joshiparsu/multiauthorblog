# Udacity Multi Author Blog project

To run this project you need to use Google AppEngine.

To use App Engine go to http://cloud.google.com/appengine and follow the directions on the page to create an account and download the client software for local testing.

From the Google App Engine Launcher go to File -> Add Existing Application... and point the launcher to the folder where you've copied these files.

This will create a local instance of the application which you can then deploy to the App Engine servers using the Deploy button.

This blog uses a signin/singout system that stores passwords and session cookies. If the user doesn't have the right cookie it will
redirect them to the login page if they try to like a post, or try to go directly to the edit, add, or delete pages. It's configured to work on /postdetail off of the root directory. 

Users can comment on any post. They can edit or delete their own posts or comments. They can like the posts of other users but not their own. If they click on the like icon (a thumb up icon) it will toggle their like on and off.

Note this is not a very secure system as users can use any password, and the email field is optional. Usernames do have to be unique.

You can see this project in working order at https://udacityblogproject-231983.appspot.com