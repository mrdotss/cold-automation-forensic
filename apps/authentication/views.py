from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
from django.views import View
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.conf import settings
from django.contrib.auth import logout
from .forms import SignUpForm, LoginForm


# Create your views here.
class LoginInvestigator(View):
    """
    The LoginInvestigator class is a view class that handles the login functionality.

    Methods:
    - dispatch: This method is called when a request is made to the view. It checks if the user is already authenticated, and if so, redirects them to the dashboard. Otherwise, it calls
    * the dispatch method of the parent class.
    - get: This method handles the GET request for the login page. It creates an instance of the LoginForm class, renders the login template, and returns the HttpResponse with the rendered
    * template.
    - post: This method handles the POST request for the login page. It validates the form data, authenticates the user, and if successful, logs the user in. If the "remember me" checkbox
    * is checked, the session expiration time is set to the default value from settings. If not, the session is set to expire when the user closes their browser. If the authentication fails
    *, an error message is added to the request messages and the user is redirected to the login page with an error message.

    Note: This class assumes the use of other classes like LoginForm and settings from Django.
    """
    def dispatch(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect('dashboard')
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        form = LoginForm()
        context = {
            'form': form
        }
        html_template = loader.get_template('home/login.html')
        return HttpResponse(html_template.render(context, request))

    def post(self, request):
        msg = None
        form = LoginForm(request.POST or None)
        if form.is_valid():
            user_email = form.cleaned_data.get("user_email")
            password = form.cleaned_data.get("password")
            remember_me = request.POST.get('remember_me')
            user = authenticate(username=user_email, password=password)
            if user is not None:
                login(request, user)
                if remember_me:
                    # Use the default session expiration time from settings (e.g., 2 weeks)
                    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                else:
                    # Expire the session when the user closes their browser
                    request.session.set_expiry(0)
                return redirect('dashboard')
            else:
                msg = 'Invalid credentials'
                messages.error(request, msg)
                return redirect('caf_login')
        else:
            msg = 'Form is not valid'
            messages.error(request, msg)
            return redirect('caf_login')


class RegisterInvestigator(View):
    """

    RegisterInvestigator

    A class-based view for registering an investigator.

    Methods:
    - dispatch: Overrides the dispatch method of the parent class to check if the user is authenticated. If authenticated, it redirects to the dashboard page. Otherwise, it calls the dispatch
    * method of the parent class.
    - get: Handles the GET request for the registration page. Renders the registration form and passes it to the template along with the necessary context. Returns the rendered template
    *.
    - post: Handles the POST request for the registration form. Validates the form, saves the user if the form is valid, and creates a session for the user. Displays success or error messages
    * accordingly and redirects to the appropriate page.

    """
    def dispatch(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect('dashboard')
        return super().dispatch(*args, **kwargs)

    def get(self, request):

        form = SignUpForm()
        context = {
            'form': form
        }
        html_template = loader.get_template('home/register.html')

        return HttpResponse(html_template.render(context, request))

    def post(self, request):
        msg = None
        form = SignUpForm(request.POST or None)
        if form.is_valid():
            form.save()
            user_mail = form.cleaned_data.get("user_email")
            raw_password = form.cleaned_data.get("password1")
            user = authenticate(username=user_mail, password=raw_password)
            msg = 'User created, please you can login now.'
            messages.success(request, msg)
            return redirect('caf_login')
        else:
            msg = 'Form is not valid'
            messages.error(request, msg)
            return redirect('caf_register')


# Logout
def logoutInvestigator(request):
    logout(request)
    return redirect('caf_login')
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        