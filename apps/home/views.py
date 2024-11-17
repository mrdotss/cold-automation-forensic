from urllib.parse import parse_qs
from django.db.models import F
from django.views import View
from django.template import loader
from django.urls import reverse_lazy
from django.forms import formset_factory
from django.http import HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, get_object_or_404, redirect
from django.core.serializers.json import DjangoJSONEncoder
from django.views.generic import ListView, CreateView, UpdateView, DeleteView

from ..caf.ColdForensic import ColdForensic
from .models import Case, User, Evidence, Acquisition, PhysicalAcquisition, FullFileSystemAcquisition, SelectiveFullFileSystemAcquisition
from .forms import CaseUpdateForm, EvidenceUpdateForm, ChainOfCustodyForm, AdditionalInfoForm
from apps.home.asynchronous.task import physicalAcquisition, selectiveFfsAcquisition
import time, random, string, json, uuid, os
from datetime import datetime


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
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case
    fields = '__all__'
    template_name = 'home/case.html'
    success_url = reverse_lazy('cases_home:all')


class CaseCreateView(CreateView):
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case
    template_name = 'home/case_create.html'
    fields = ['case_number', 'description', 'case_name', 'case_is_open', 'case_member']

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)
        self.object.case_member.add(self.request.user.id)
        self.object.case_member.add(*self.request.POST.getlist('case_member'))

        additional_info = {}
        additional_info.update({
            'addinfo_name': self.request.POST.get('addinfo_name'),
            'addinfo_agency': self.request.POST.get('addinfo_agency'),
            'addinfo_phone': self.request.POST.get('addinfo_phone'),
            'addinfo_fax': self.request.POST.get('addinfo_fax'),
            'addinfo_address': self.request.POST.get('addinfo_address'),
            'addinfo_email': self.request.POST.get('addinfo_email'),
            'addinfo_notes': self.request.POST.get('addinfo_notes'),
        })

        self.object.additional_info = additional_info
        self.object.save()
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['home_user_list'] = User.objects.exclude(id=self.request.user.id)
        return context

    def get_success_url(self):
        return reverse_lazy('cases_home')


class CaseUpdateView(UpdateView):
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Case
    template_name = 'home/case_update.html'
    form_class = CaseUpdateForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Check if additional_info exists
        has_additional_info = bool(self.object.additional_info)

        if has_additional_info:
            extra = 0
            if isinstance(self.object.additional_info, list):
                initial_data = self.object.additional_info
            else:
                initial_data = [self.object.additional_info]
        else:
            extra = 1  # Provide one empty form when no additional_info exists
            initial_data = []

        # Create the formset with the determined 'extra' value
        AdditionalInfoFormSet = formset_factory(AdditionalInfoForm, extra=extra)

        if self.request.method == 'POST':
            context['additional_info_formset'] = AdditionalInfoFormSet(self.request.POST)
        else:
            context['additional_info_formset'] = AdditionalInfoFormSet(initial=initial_data)

        return context

    def get_success_url(self):
        return reverse_lazy('cases_home')

    def get_object(self, queryset=None):
        case_id = self.kwargs['case_id']
        return get_object_or_404(Case, case_id=case_id)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['current_user'] = self.request.user  # Pass current user to the form
        return kwargs

    def form_valid(self, form):
        context = self.get_context_data()
        additional_info_formset = context['additional_info_formset']

        if additional_info_formset.is_valid():
            response = super().form_valid(form)
            case = self.object

            # Get selected members from the form
            selected_members = form.cleaned_data['case_member']

            # Ensure the creator is included in the case members
            selected_members = list(selected_members)  # Convert to list to allow modification
            if case.user.id not in selected_members:
                selected_members.append(self.request.user)

            # Update the case members
            case.case_member.set(selected_members)

            additional_info = {}
            for form in additional_info_formset.cleaned_data:
                if not form.get('DELETE', False):
                    additional_info.update({
                        'addinfo_name': form.get('addinfo_name'),
                        'addinfo_agency': form.get('addinfo_agency'),
                        'addinfo_phone': form.get('addinfo_phone'),
                        'addinfo_fax': form.get('addinfo_fax'),
                        'addinfo_address': form.get('addinfo_address'),
                        'addinfo_email': form.get('addinfo_email'),
                        'addinfo_notes': form.get('addinfo_notes'),
                    })

            self.object.additional_info = additional_info
            self.object.save()
            return response
        else:
            return super().form_invalid(form)


class CaseDeleteView(DeleteView):
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


def get_case_members(request, case_id):
    case = get_object_or_404(Case, case_id=case_id)
    members = case.case_member.all().values('id', 'user_name', 'user_roles')
    return JsonResponse(list(members), safe=False)


def get_evidence_modal_data(request, evidence_id):
    evidence = Evidence.objects.get(evidence_id=evidence_id)
    return render(request, 'includes/evidence_modal.html', {'evidence': evidence})

def get_evidence_acquisition_history(request, evidence_id):
    acquisition = Acquisition.objects.filter(evidence=evidence_id)
    evidence = Evidence.objects.get(evidence_id=evidence_id)
    return render(request, 'includes/evidence_acquisition_history.html', {'acquisition': acquisition, 'evidence': evidence})

def get_acquisition_presetup(request, serial_id, unique_link):
    acquisitionObject = Acquisition.objects.get(unique_link=unique_link)

    print(f"Serial: {serial_id} | Unique: {unique_link} | Object: {acquisitionObject}")

    if acquisitionObject.status in ["in_progress", "pending", "failed", "cancelled"]:

        if acquisitionObject.status in ["failed", "cancelled"]:
            # Resume the failed acquisition
            acquisitionObject.status = "in_progress"
            acquisitionObject.save()

        if acquisitionObject.acquisition_type == "physical":
            result = physicalAcquisition.delay('acquisition-progress_%s' % unique_link, unique_link)

            if result.failed():
                print("Failed ->", result.traceback)
        elif acquisitionObject.acquisition_type == "selective_full_file_system":
            result = selectiveFfsAcquisition.delay('acquisition-progress_%s' % unique_link, unique_link)

            if result.failed():
                print("Failed ->", result.traceback)

        print("Status ->", result.status)  # This will print the current status of the task

    if ColdForensic().checkSerialID(serial_id) and acquisitionObject:
        return render(request, 'includes/acquisition_setup.html', {})
    else:
        return HttpResponse("Serial ID not found")

def get_acquisition_setup(request, serial_id, unique_link):
    isUniqueCode = Acquisition.objects.filter(unique_link=unique_link).exists()

    if ColdForensic().checkSerialID(serial_id) and isUniqueCode:
        getAcquisitionObject = Acquisition.objects.get(unique_link=unique_link)

        if getAcquisitionObject.status in ["in_progress", "pending", "cancelled", "failed"]:
            if getAcquisitionObject.acquisition_type == "physical":
                return render(request, 'includes/acquisition_progress.html', {'acquisitionObject': getAcquisitionObject})
            if getAcquisitionObject.acquisition_type == "selective_full_file_system":
                return render(request, 'includes/acquisition_progress_spinner.html', {'acquisitionObject': getAcquisitionObject})

    return HttpResponse("Serial ID not found")

def get_acquisition_save_location(request, serial_id, unique_link):
    isUniqueCode = Acquisition.objects.filter(unique_link=unique_link).exists()

    if ColdForensic().checkSerialID(serial_id) and isUniqueCode:
        evidenceList = Evidence.objects.select_related('case').values(
            'evidence_id',
            'evidence_description',
            case_name=F('case__case_name')
        )

        isHashedIP = ColdForensic().is_hashed_ip_or_not(serial_id)
        isWifi = ColdForensic().check_if_hashed_ip(serial_id, ColdForensic().secret_key) if isHashedIP else False
        ipAddress = ColdForensic().decrypt(serial_id, ColdForensic().secret_key).split(':')[0] if isHashedIP else ""
        acquisitionType = Acquisition.objects.get(unique_link=unique_link).acquisition_type

        context ={
            'evidenceList': evidenceList,
            'isWifi': isWifi,
            'ipAddress': ipAddress,
            'acquisitionType': acquisitionType,
        }

        return render(request, 'includes/acquisition_save_location.html', context)
    else:
        return HttpResponse("Serial ID or Unique not found")

class EvidenceListView(ListView):
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence
    fields = '__all__'
    template_name = 'home/evidence.html'
    success_url = reverse_lazy('evidences_home:all')


class EvidenceCreateView(CreateView):

    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence
    template_name = 'home/evidence_create.html'
    fields = ['evidence_description', 'evidence_status', 'evidence_type', 'case',
              'evidence_acquired_by', 'evidence_acquired_date', 'evidence_number']

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
                'id': user,
                'user': User.objects.get(id=user).user_name,
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
        context['home_user_list'] = json.dumps(list(user_list.values('id', 'user_name')), cls=UUIDEncoder)
        return context

    def get_success_url(self):
        return reverse_lazy('evidences_home')


class EvidenceUpdateView(UpdateView):
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    model = Evidence
    template_name = 'home/evidence_update.html'
    form_class = EvidenceUpdateForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_list = User.objects.all()
        context['home_user_list'] = json.dumps(list(user_list.values('id', 'user_name')), cls=UUIDEncoder)

        ChainOfCustodyFormSet = formset_factory(ChainOfCustodyForm, extra=0)

        if self.request.method == 'POST':
            context['chain_of_custody_formset'] = ChainOfCustodyFormSet(self.request.POST)
        else:
            initial_data = self.object.evidence_chain_of_custody
            for data in initial_data:
                data['user'] = data['id']  # Set the initial value for the 'user' field to be the 'id'
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
                        'id': str(chain_of_custody_form.cleaned_data.get('user').id),
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
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        context = {
            'devList': ColdForensic().get_select_device(),
        }
        html_template = loader.get_template('home/device.html')
        return HttpResponse(html_template.render(context, request))


class DevicesDetail(View):
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
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        context = {

        }
        html_template = loader.get_template('home/analyst-report.html')
        return HttpResponse(html_template.render(context, request))


class Profiles(View):
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):

        getCaseByUser = Case.objects.filter(case_member=request.user.id).count()
        getEvidenceByUser = Evidence.objects.filter(evidence_acquired_by=request.user.id).count()

        context = {
            'getCaseByUser': getCaseByUser,
            'getEvidenceByUser': getEvidenceByUser,
        }
        html_template = loader.get_template('home/profiles.html')
        return HttpResponse(html_template.render(context, request))


class Acquisitions(View):
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, serial_id):

        isDevice = ColdForensic().checkSerialID(serial_id)
        storage = ColdForensic().getStorage(serial_id)
        appList = ColdForensic().getAppList(serial_id)
        isRooted = ColdForensic().isRooted(serial_id)

        if isDevice:
            context = {
                'serial_id': serial_id,
                'storage': storage,
                'appList': appList,
                'isRooted': isRooted,
            }
            html_template = loader.get_template('home/device-acquisition.html')
            return HttpResponse(html_template.render(context, request))
        else:
            return HttpResponse("Device not found")


class AcquisitionSetup(View):

    def get(self, request, serial_id, unique_code):
        isDevice = ColdForensic().checkSerialID(serial_id)
        acquisitionObject = Acquisition.objects.filter(unique_link=unique_code).first()

        if not isDevice or not acquisitionObject:
            return HttpResponse("Device or acquisition process not found")

        isHashedIP = ColdForensic().is_hashed_ip_or_not(serial_id)
        isWifi = ColdForensic().check_if_hashed_ip(serial_id, ColdForensic().secret_key) if isHashedIP else False

        # For FFS method
        if acquisitionObject.acquisition_type == "selective_full_file_system":
            acquisitionHistory = Acquisition.objects.filter(device_id=serial_id, acquisition_type="selective_full_file_system").order_by('-date')
            fileSystemList = ColdForensic().getFullFileSystem(serial_id)

            context = {
                'serial_id': serial_id,
                'file_system_list': fileSystemList,
                'acquisitionHistory': acquisitionHistory,
                'acquisitionProcess': acquisitionObject,
                'isWifi': isWifi
            }

            if isHashedIP:
                context = {
                    'serial_id': serial_id,
                    'acquisitionProcess': acquisitionObject,
                    'file_system_list': fileSystemList,
                    'acquisitionHistory': acquisitionHistory,
                    'isWifi': isWifi,
                    'ipAddress': ColdForensic().decrypt(serial_id, ColdForensic().secret_key).split(':')[0]
                }

            return render(request, 'home/device-acquisition-ffs-setup.html', context)

        # Combine filtering and sorting in one query for clarity and efficiency
        acquisitionList = Acquisition.objects.filter(
            device_id=serial_id,
            acquisition_type='physical'
        ).exclude(status='pending').order_by('-date')

        # Extract and calculate percentages in a more Pythonic way
        percentageList = [
            {
                'percentage': int(100 * (int(data['physical__total_transferred_bytes']) /
                                         (int(data['physical__partition_size']) * 1024)))
            }
            for data in acquisitionList.values('physical__total_transferred_bytes', 'physical__partition_size')
        ]

        acquisitionHistory = zip(acquisitionList, percentageList)

        # Check if the acquisition needs to resume
        if hasattr(acquisitionObject, 'physical') and acquisitionObject.physical.total_transferred_bytes >= 0 and acquisitionObject.status in ["cancelled", "failed", "in_progress"]:

            # Prepare the context for rendering
            context = {
                'serial_id': serial_id,
                'acquisitionProcess': acquisitionObject,
                'acquisitionHistory': acquisitionHistory,
                'acquisitionPercentage': percentageList,
            }

            if isHashedIP:
                context = {
                    'serial_id': serial_id,
                    'acquisitionProcess': acquisitionObject,
                    'acquisitionHistory': acquisitionHistory,
                    'acquisitionPercentage': percentageList,
                    'isWifi': isWifi,
                    'ipAddress': ColdForensic().decrypt(serial_id, ColdForensic().secret_key).split(':')[0]
                }

            return render(request, 'home/device-acquisition-resume.html', context)

        if acquisitionObject.status in ["completed"]:
            return HttpResponse(f"Task already {acquisitionObject.status}")

        partitionList = ColdForensic().getPartitionList(serial_id)

        context = {
            'serial_id': serial_id,
            'partitionList': partitionList,
            'acquisitionProcess': acquisitionObject,
            'acquisitionHistory': acquisitionHistory,
            'isWifi': isWifi,
        }

        if isHashedIP:
            context = {
                'serial_id': serial_id,
                'partitionList': partitionList,
                'acquisitionProcess': acquisitionObject,
                'acquisitionHistory': acquisitionHistory,
                'isWifi': isWifi,
                'ipAddress': ColdForensic().decrypt(serial_id, ColdForensic().secret_key).split(':')[0]
            }

        return render(request, 'home/device-acquisition-physical-setup.html', context)

    def post(self, request, serial_id, unique_code):
        isDevice = ColdForensic().checkSerialID(serial_id)
        acquisitionObject = Acquisition.objects.filter(unique_link=unique_code).first()

        if not isDevice or not acquisitionObject:
            return HttpResponse("Device or acquisition process not found")

        data = {key: value for key, value in request.POST.items() if key != 'csrfmiddlewaretoken'}

        # Check if the device is connected via WiFi or USB
        isHashedIP = ColdForensic().is_hashed_ip_or_not(serial_id)
        isWifi = ColdForensic().check_if_hashed_ip(serial_id, ColdForensic().secret_key) if isHashedIP else False

        connection_type = 'WiFi' if isWifi else 'USB'

        if acquisitionObject.acquisition_type == "physical":
            # Get current time
            current_time = time.strftime("%Y%m%d%H%M%S")

            # Generate a random string for unique identifier
            unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

            acquisition_file_name = f"{data['partition_id']}_{current_time}_{unique_id}_{connection_type.lower()}.dd"

            # Convert checkbox_value to boolean or integer
            acquisition_is_verify_first = data['checkbox_value'] == 'true'

            # Retrieve the evidence object based on the provided evidence_name
            evidence = Evidence.objects.get(evidence_id=data['evidence_name'])

            # Calculate the acquisition size template (convert partition size to MB)
            acquisition_size_template = round(int(data['partition_size']) / 1000000, 2)

            # Check if a PhysicalAcquisition already exists for this Acquisition
            physical_acquisition, created = PhysicalAcquisition.objects.get_or_create(
                acquisition=acquisitionObject,
                defaults={
                    'partition_id': data['partition_id'],
                    'partition_size': data['partition_size'],
                    'is_verify_first': acquisition_is_verify_first,
                    'acquisition_method': "dd",
                    'source_device': f"/dev/block/{data['partition_id']}",
                }
            )

            # If it already exists, you can update the necessary fields
            if not created:
                physical_acquisition.partition_id = data['partition_id']
                physical_acquisition.partition_size = data['partition_size']
                physical_acquisition.is_verify_first = acquisition_is_verify_first
                physical_acquisition.acquisition_method = "dd"
                physical_acquisition.source_device = f"/dev/block/{data['partition_id']}"
                physical_acquisition.save()

            base_path = data['full_path']
            # Generate a unique and structured folder name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            folderName = f"evidence_{timestamp}_{random_suffix}"

            try:
                os.makedirs(f"{base_path}/{folderName}", exist_ok=True)
                print(f"Folder created at {base_path}/{folderName}")
            except OSError as e:
                print(f"Failed to create directory {base_path}/{folderName}: {e}")

            acquisitionObject.evidence_id = evidence.evidence_id
            acquisitionObject.connection_type = connection_type
            acquisitionObject.full_path = f"{base_path}/{folderName}"
            acquisitionObject.file_name = acquisition_file_name

            acquisitionObject.client_ip = data.get('client_ip') if data.get('client_ip') != "USB" else ""  # Handle optional fields safely
            acquisitionObject.port = data.get('port') if data.get('port') != "USB" else ""
            acquisitionObject.status = "in_progress"
            acquisitionObject.size = round(int(data['partition_size']) / 1000000, 2)

            # Save the updated acquisition object
            acquisitionObject.save()

            print("POST Data ->", data)
            return HttpResponse("Task started..")

        elif acquisitionObject.acquisition_type == "selective_full_file_system":

            # If app_list is missing in data, retrieve it directly from request.body
            if 'app_list' not in data:
                raw_body = request.body.decode('utf-8')  # Decode the raw body to a string
                parsed_body = parse_qs(raw_body)  # Parse the query string to a dictionary
                app_list_str = parsed_body.get('app_list', ['[]'])[
                    0]  # Extract app_list, defaulting to '[]' if not found
            else:
                app_list_str = data.get('app_list', '[]')

            # Convert app_list JSON string to a Python list
            try:
                app_list = json.loads(app_list_str)
            except json.JSONDecodeError:
                app_list = []

            # Retrieve the evidence object based on the provided evidence_name
            evidence = Evidence.objects.get(evidence_id=data['evidence_name'])

            selective_ffs_acquisition, created = SelectiveFullFileSystemAcquisition.objects.get_or_create(
                acquisition=acquisitionObject,
                defaults={
                    'acquisition_tool': 'tar,netcat',
                    'selected_applications': json.loads(data['app_list']),
                    'total_records': len(json.loads(data['app_list'])),
                }
            )

            if not created:
                selective_ffs_acquisition.acquisition_tool = 'tar,netcat'
                selective_ffs_acquisition.selected_applications = json.loads(data['app_list'])
                selective_ffs_acquisition.total_records = len(json.loads(data['app_list']))
                selective_ffs_acquisition.save()

            base_path = data['full_path']
            # Generate a unique and structured folder name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            folderName = f"evidence_{timestamp}_{random_suffix}"

            try:
                os.makedirs(f"{base_path}/{folderName}", exist_ok=True)
                print(f"Folder created at {base_path}/{folderName}")
            except OSError as e:
                print(f"Failed to create directory {base_path}/{folderName}: {e}")

            # Update acquisition object
            acquisitionObject.evidence_id = evidence.evidence_id
            acquisitionObject.connection_type = connection_type
            acquisitionObject.full_path = f"{base_path}/{folderName}"
            acquisitionObject.client_ip = data.get('client_ip') if data.get('client_ip') != "USB" else ""  # Handle optional fields safely
            acquisitionObject.port = data.get('port') if data.get('port') != "USB" else ""
            acquisitionObject.status = "in_progress"

            # Save the updated acquisition object
            acquisitionObject.save()

            print("POST Data ->", data)
            return HttpResponse("Task started..")


class GenerateUniqueCodeView(View):
    def get(self, request, serial_id, acquire_method):
        # Check if the device is valid
        isDevice = ColdForensic().checkSerialID(serial_id)
        if isDevice:

            device = serial_id
            if len(serial_id) > 15 and ColdForensic().checkSerialID(serial_id):
                device = ColdForensic().decrypt(serial_id, ColdForensic().secret_key)

            # Generate and save the new Acquisition process
            unique_code = uuid.uuid4()
            Acquisition.objects.create(
                device_id=serial_id,
                unique_link=unique_code,
                acquisition_type=acquire_method,
                serial_number=ColdForensic().decode_bytes_property(ColdForensic().getProp(device, 'ro.serialno', 'unknown')),
            )
            return JsonResponse({'success': True, 'unique_code': str(unique_code)})
        else:
            return JsonResponse({'success': False}, status=400)