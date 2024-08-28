from django.db.models import F
from django.views import View
from django.template import loader
from django.urls import reverse_lazy
from django.forms import formset_factory
from django.http import HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.core.serializers.json import DjangoJSONEncoder
from django.views.generic import ListView, CreateView, UpdateView, DeleteView

from ..caf.ColdForensic import ColdForensic
from .models import Case, User, Evidence, Acquisition
from .forms import CaseUpdateForm, EvidenceUpdateForm, ChainOfCustodyForm
from apps.home.asynchronous.task import physicalAcquisition
import time, random, string, json, uuid


class UUIDEncoder(DjangoJSONEncoder):
    """
    Class: UUIDEncoder

    Inherits: DjangoJSONEncoder

    Description:
    This class is responsible for encoding UUID objects into JSON serializable format by extending the DjangoJSONEncoder class.

    Methods:
    1. default(self, obj)
        - Description: This method overrides the default method of DjangoJSONEncoder class to encode UUID objects.
        - Parameter:
            - obj: The object to be encoded into JSON serializable format.
        - Returns:
            - If the object is an instance of UUID, it returns the string representation of the UUID.
            - Otherwise, it calls the default method of the parent class to handle the encoding.

    """
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return super().default(obj)


class Dashboard(View):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):

        totalInvestigator = User.objects.filter(user_roles='Investigator').count()
        totalCases = Case.objects.count()
        totalEvidences = Evidence.objects.count()

        context = {
            'totalInvestigator': totalInvestigator,
            'totalCases': totalCases,
            'totalEvidences': totalEvidences,
        }
        html_template = loader.get_template('home/index.html')
        return HttpResponse(html_template.render(context, request))


class CaseListView(ListView):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case
    fields = '__all__'
    template_name = 'home/case.html'
    success_url = reverse_lazy('cases_home:all')


class CaseCreateView(CreateView):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case
    template_name = 'home/case_create.html'
    fields = ['case_name', 'case_is_open', 'case_member']

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)
        self.object.case_member.add(self.request.user.user_id)
        self.object.case_member.add(*self.request.POST.getlist('case_member'))
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['home_user_list'] = User.objects.exclude(user_id=self.request.user.user_id)
        return context

    def get_success_url(self):
        return reverse_lazy('cases_home')


class CaseUpdateView(UpdateView):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case
    template_name = 'home/case_update.html'
    form_class = CaseUpdateForm

    def get_success_url(self):
        return reverse_lazy('cases_home')

    def get_object(self, queryset=None):
        case_id = self.kwargs['case_id']
        return get_object_or_404(Case, case_id=case_id)


class CaseDeleteView(DeleteView):
    @method_decorator(login_required(login_url='caf_login'))
    @method_decorator(csrf_exempt)  # To allow AJAX POST requests without CSRF token
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case

    def get_object(self, queryset=None):
        case_id = self.kwargs['case_id']
        return get_object_or_404(Case, case_id=case_id)

    def form_valid(self, form):
        self.object = self.get_object()
        self.object.delete()
        return JsonResponse({'success': True})

    def get_success_url(self):
        return reverse_lazy('cases_home')


@login_required(login_url='caf_login')
def get_case_members(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    members = case.case_member.all().values('user_id', 'user_name')
    return JsonResponse(list(members), safe=False)


@login_required(login_url='caf_login')
def get_evidence_modal_data(request, evidence_id):
    evidence = Evidence.objects.get(evidence_id=evidence_id)
    return render(request, 'includes/evidence_modal.html', {'evidence': evidence})

@login_required(login_url='caf_login')
def get_acquisition_presetup(request, serial_id, unique_code):
    acquisitionObject = Acquisition.objects.filter(acquisition_unique_link=unique_code).first()

    if acquisitionObject.acquisition_status in ["progress", "pending", "failed"]:

        if acquisitionObject.acquisition_status == "failed":
            # Resume the failed acquisition
            acquisitionObject.acquisition_status = "progress"
            acquisitionObject.save()

        result = physicalAcquisition.delay('physical-acquisition-progress_%s' % serial_id, unique_code)

        if result.failed():
            print("Failed ->", result.traceback)

        print("Status ->", result.status)  # This will print the current status of the task

    if ColdForensic().checkSerialID(serial_id) and acquisitionObject:
        return render(request, 'includes/acquisition_setup.html', {})
    else:
        return HttpResponse("Serial ID not found")

@login_required(login_url='caf_login')
def get_acquisition_setup(request, serial_id, unique_code):
    isUniqueCode = Acquisition.objects.filter(acquisition_unique_link=unique_code).exists()

    if ColdForensic().checkSerialID(serial_id) and isUniqueCode:
        getAcquisitionObject = Acquisition.objects.get(acquisition_unique_link=unique_code)

        if getAcquisitionObject.acquisition_status in ["progress", "pending", "failed"]:
            return render(request, 'includes/acquisition_progress.html', {'acquisitionObject': getAcquisitionObject})
        # if getAcquisitionObject.acquisition_status in ["failed"]:
        #     return render(request, 'home/device-acquisition-resume.html', {'acquisitionObject': getAcquisitionObject})

    return HttpResponse("Serial ID not found")

@login_required(login_url='caf_login')
def get_acquisition_save_location(request, serial_id, unique_code):
    isUniqueCode = Acquisition.objects.filter(acquisition_unique_link=unique_code).exists()

    if ColdForensic().checkSerialID(serial_id) and isUniqueCode:
        evidenceList = Evidence.objects.select_related('case').values(
            'evidence_id',
            'evidence_description',
            case_name=F('case__case_name')
        )

        return render(request, 'includes/acquisition_save_location.html',
                      {'evidenceList': evidenceList})
    else:
        return HttpResponse("Serial ID or Unique not found")

class EvidenceListView(ListView):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence
    fields = '__all__'
    template_name = 'home/evidence.html'
    success_url = reverse_lazy('evidences_home:all')


class EvidenceCreateView(CreateView):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence
    template_name = 'home/evidence_create.html'
    fields = ['evidence_description', 'evidence_status', 'evidence_type', 'case',
              'evidence_acquired_by', 'evidence_acquired_date']

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)
        coc_dates = self.request.POST.getlist('coc_date')
        coc_users = self.request.POST.getlist('coc_user')
        coc_actions = self.request.POST.getlist('coc_action')
        coc_details = self.request.POST.getlist('coc_details')

        chain_of_custody_data = []
        for date, user, action, detail in zip(coc_dates, coc_users, coc_actions, coc_details):
            chain_of_custody_data.append({
                'date': date,
                'user_id': user,
                'user': User.objects.get(user_id=user).user_name,
                'action': action,
                'detail': detail
            })
        self.object.evidence_chain_of_custody = chain_of_custody_data
        self.object.save()

        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['home_case_list'] = Case.objects.all()
        user_list = User.objects.all()
        context['home_user_list'] = json.dumps(list(user_list.values('user_id', 'user_name')), cls=UUIDEncoder)
        return context

    def get_success_url(self):
        return reverse_lazy('evidences_home')


class EvidenceUpdateView(UpdateView):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence
    template_name = 'home/evidence_update.html'
    form_class = EvidenceUpdateForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_list = User.objects.all()
        context['home_user_list'] = json.dumps(list(user_list.values('user_id', 'user_name')), cls=UUIDEncoder)

        ChainOfCustodyFormSet = formset_factory(ChainOfCustodyForm, extra=0)

        if self.request.method == 'POST':
            context['chain_of_custody_formset'] = ChainOfCustodyFormSet(self.request.POST)
        else:
            initial_data = self.object.evidence_chain_of_custody
            for data in initial_data:
                data['user'] = data['user_id']  # Set the initial value for the 'user' field to be the 'user_id'
            context['chain_of_custody_formset'] = ChainOfCustodyFormSet(initial=initial_data)

        return context

    def get_success_url(self):
        return reverse_lazy('evidences_home')

    def get_object(self, queryset=None):
        evidence_id = self.kwargs['evidence_id']
        return get_object_or_404(Evidence, evidence_id=evidence_id)

    def form_valid(self, form):
        context = self.get_context_data()
        chain_of_custody_formset = context['chain_of_custody_formset']

        if chain_of_custody_formset.is_valid():
            response = super().form_valid(form)

            chain_of_custody_data = []

            for chain_of_custody_form in chain_of_custody_formset:
                if chain_of_custody_form.cleaned_data and not chain_of_custody_form.cleaned_data.get('DELETE'):
                    coc_data = {
                        'date': str(chain_of_custody_form.cleaned_data.get('date')),
                        'user_id': str(chain_of_custody_form.cleaned_data.get('user').user_id),
                        'user': chain_of_custody_form.cleaned_data.get('user').user_name,
                        'action': chain_of_custody_form.cleaned_data.get('action'),
                        'detail': chain_of_custody_form.cleaned_data.get('detail')
                    }
                    print("Isi COC ->", coc_data)
                    chain_of_custody_data.append(coc_data)

            self.object.evidence_chain_of_custody = chain_of_custody_data
            self.object.save()

            return response
        else:
            return super().form_invalid(form)


class EvidenceDeleteView(DeleteView):
    @method_decorator(login_required(login_url='caf_login'))
    @method_decorator(csrf_exempt)  # To allow AJAX POST requests without CSRF token
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence

    def get_object(self, queryset=None):
        evidence_id = self.kwargs['evidence_id']
        return get_object_or_404(Evidence, evidence_id=evidence_id)

    def form_valid(self, form):
        self.object = self.get_object()
        self.object.delete()
        return JsonResponse({'success': True})

    def get_success_url(self):
        return reverse_lazy('evidences_home')


class Devices(View):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        context = {
            'devList': ColdForensic().get_select_device(),
        }
        html_template = loader.get_template('home/device.html')
        return HttpResponse(html_template.render(context, request))


class DevicesDetail(View):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, dev_id):
        context = {
            'isWiFi': 'true',
            'deviceID': dev_id,

        }
        html_template = loader.get_template('home/device-detail.html')
        return HttpResponse(html_template.render(context, request))


class Analysts(View):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        context = {

        }
        html_template = loader.get_template('home/analyst-report.html')
        return HttpResponse(html_template.render(context, request))


class Profiles(View):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):

        getCaseByUser = Case.objects.filter(case_member=request.user.user_id).count()
        getEvidenceByUser = Evidence.objects.filter(evidence_acquired_by=request.user.user_id).count()

        context = {
            'getCaseByUser': getCaseByUser,
            'getEvidenceByUser': getEvidenceByUser,
        }
        html_template = loader.get_template('home/profiles.html')
        return HttpResponse(html_template.render(context, request))


class Acquisitions(View):
    @method_decorator(login_required(login_url='caf_login'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, serial_id):

        isDevice = ColdForensic().checkSerialID(serial_id)
        storage = ColdForensic().getStorage(serial_id)
        appList = ColdForensic().getAppList(serial_id)

        if isDevice:

            context = {
                'serial_id': serial_id,
                'storage': storage,
                'appList': appList,
            }
            html_template = loader.get_template('home/device-acquisition.html')
            return HttpResponse(html_template.render(context, request))
        else:
            return HttpResponse("Device not found")


@method_decorator(login_required(login_url='caf_login'), name='dispatch')
class AcquisitionSetup(View):

    def get(self, request, serial_id, unique_code):
        isDevice = ColdForensic().checkSerialID(serial_id)
        acquisitionObject = Acquisition.objects.filter(acquisition_unique_link=unique_code).first()

        if not isDevice or not acquisitionObject:
            return HttpResponse("Device or acquisition process not found")

        acquisitionHistory = Acquisition.objects.filter(acquisition_device_id=serial_id).values(
            'acquisition_id', 'acquisition_status', 'acquisition_full_path', 'acquisition_file_name',
            'acquisition_date', 'acquisition_partition_id', 'acquisition_size', 'acquisition_unique_link',
            'acquisition_hash'
        )

        # Check if the acquisition needs to resume
        if acquisitionObject.acquisition_total_transferred_bytes > 0 and acquisitionObject.acquisition_status == "failed":
            context = {
                'serial_id': serial_id,
                'acquisitionProcess': acquisitionObject,
                'acquisitionHistory': acquisitionHistory,
            }
            return render(request, 'home/device-acquisition-resume.html', context)

        if acquisitionObject.acquisition_status in ["completed"]:
            return HttpResponse(f"Task already {acquisitionObject.acquisition_status}")

        partitionList = ColdForensic().getPartitionList(serial_id)

        context = {
            'serial_id': serial_id,
            'partitionList': partitionList,
            'acquisitionProcess': acquisitionObject,
            'acquisitionHistory': acquisitionHistory,
        }

        return render(request, 'home/device-acquisition-setup.html', context)

    def post(self, request, serial_id, unique_code):
        isDevice = ColdForensic().checkSerialID(serial_id)
        acquisitionObject = Acquisition.objects.filter(acquisition_unique_link=unique_code).first()

        if not isDevice or not acquisitionObject:
            return HttpResponse("Device or acquisition process not found")

        data = {key: value for key, value in request.POST.items() if key != 'csrfmiddlewaretoken'}

        # Get current time
        current_time = time.strftime("%Y%m%d%H%M%S")

        # Generate a random string for unique identifier
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

        if ColdForensic().check_if_hashed_ip(serial_id, ColdForensic().secret_key):
            acquisition_file_name = f"{data['partition_id']}_{current_time}_{unique_id}_wifi.dd"
        else:
            acquisition_file_name = f"{data['partition_id']}_{current_time}_{unique_id}_usb.dd"

        # Convert checkbox_value to boolean or integer
        acquisition_is_verify_first = data['checkbox_value'] == 'true'

        # Update acquisition object
        evidence = Evidence.objects.get(evidence_id=data['evidence_name'])
        Acquisition.objects.filter(acquisition_unique_link=unique_code).update(
            evidence_id=evidence.evidence_id,
            acquisition_is_verify_first=acquisition_is_verify_first,
            acquisition_type=evidence.evidence_type,
            acquisition_partition_id=data['partition_id'],
            acquisition_size=data['partition_size'],
            acquisition_file_name=acquisition_file_name,
            acquisition_full_path=data['full_path'],
            acquisition_client_ip=data['client_ip'],
            acquisition_custom_port=data['custom_port'],
            acquisition_status="progress",
            acquisition_size_template=round(int(data['partition_size']) / 1000000, 2)
        )

        print("POST Data ->", data)
        return HttpResponse("Task started..")


class GenerateUniqueCodeView(View):
    @method_decorator(login_required(login_url='caf_login'))
    def get(self, request, serial_id):
        # Check if the device is valid
        isDevice = ColdForensic().checkSerialID(serial_id)
        if isDevice:
            # Generate and save the new Acquisition process
            unique_code = uuid.uuid4()
            Acquisition.objects.create(
                acquisition_device_id=serial_id,
                acquisition_unique_link=unique_code
            )
            return JsonResponse({'success': True, 'unique_code': str(unique_code)})
        else:
            return JsonResponse({'success': False}, status=400)