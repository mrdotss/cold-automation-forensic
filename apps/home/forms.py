from django import forms
from .models import User, Case, Evidence

EVIDENCE_TYPE_CHOICES = [('Physical', 'Physical'), ('Digital', 'Digital')]
EVIDENCE_STATUS_CHOICES = [('Acquired', 'Acquired'), ('Analyzed', 'Analyzed'), ('Archived', 'Archived')]


# Creating form
class CaseUpdateForm(forms.ModelForm):
    case_number = forms.CharField(
        label='case_number',
        widget=forms.TextInput(
            attrs={
                "placeholder": "Case Number",
                "class": "form-control",
                "autofocus": "true",
            }
        ), required=True
    )
    case_name = forms.CharField(
        label='case_name',
        widget=forms.TextInput(
            attrs={
                "placeholder": "Case Name",
                "class": "form-control",
                "autofocus": "true",
            }
        ), required=True
    )
    description = forms.CharField(
        label='case_number',
        widget=forms.Textarea(
            attrs={
                "placeholder": "Some description..",
                "class": "form-control",
                "autofocus": "true",
                "rows": "",
                "cols": "",
            }
        ), required=True
    )
    case_is_open = forms.BooleanField(
        label='case_is_open',
        widget=forms.CheckboxInput(
            attrs={
                "class": "custom-control-input",
                "id": "customCheck1",
            }
        ), required=True
    )
    case_member = forms.ModelMultipleChoiceField(
        label='case_member',
        widget=forms.SelectMultiple(
            attrs={
                "class": "form-control selectpicker",
                "data-live-search": "true",
                "multiple": "multiple",
                "data-height": "100%",
            }
        ), queryset=User.objects.all(), required=True
    )

    class Meta:
        model = Case
        fields = ['case_number', 'description', 'case_name', 'case_member', 'case_is_open', 'additional_info']

    def __init__(self, *args, **kwargs):
        current_user = kwargs.pop('current_user', None)  # Extract current_user from kwargs
        super(CaseUpdateForm, self).__init__(*args, **kwargs)
        if current_user:
            # Exclude the current user from the queryset
            self.fields['case_member'].queryset = User.objects.exclude(id=current_user.id)


class EvidenceUpdateForm(forms.ModelForm):
    case = forms.ModelChoiceField(
        label='case',
        widget=forms.Select(
            attrs={
                "class": "form-control select2",
                "id": "case",
            }
        ), queryset=Case.objects.all(), required=True
    )
    evidence_acquired_by = forms.ChoiceField(
        label='evidence_acquired_by',
        widget=forms.Select(
            attrs={
                "class": "form-control",
                "id": "evidence_acquired_by",
            }
        ), required=True
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # Get the evidence instance
            evidence = self.instance
            # Get the case associated with the evidence
            case = evidence.case
            # Get the evidence_acquired_by for the case
            acquired_by = case.case_member.all()
            # Create choices for the evidence_acquired_by field
            self.fields['evidence_acquired_by'].choices = [(member.id, member.user_name) for member in acquired_by]
            # Set the initial value of evidence_acquired_by to the existing value
            self.fields['evidence_acquired_by'].initial = evidence.evidence_acquired_by.id

    evidence_description = forms.CharField(
        label='evidence_description',
        widget=forms.Textarea(
            attrs={
                "placeholder": "Some description..",
                "class": "form-control",
                "autofocus": "true",
            }
        )
    )
    evidence_number = forms.CharField(
        label='evidence_number',
        widget=forms.TextInput(
            attrs={
                "placeholder": "Ex: 001",
                "class": "form-control",
                "autofocus": "true",
            }
        )
    )
    evidence_type = forms.ChoiceField(
        label='evidence_type',
        choices=EVIDENCE_TYPE_CHOICES,
        widget=forms.RadioSelect(
            attrs={
                "class": "custom-control-input",
                "autofocus": "true",
            }
        )
    )
    evidence_status = forms.ChoiceField(
        label='evidence_status',
        choices=EVIDENCE_STATUS_CHOICES,
        widget=forms.Select(
            attrs={
                "class": "form-control selectric",
                "id": "evidence_status",
            }
        ), required=True
    )
    evidence_acquired_date = forms.CharField(
        label='evidence_acquired_date',
        widget=forms.TextInput(
            attrs={
                "class": "form-control datepicker",
            }
        ), required=True
    )

    def clean_evidence_acquired_by(self):
        user_id = self.cleaned_data.get('evidence_acquired_by')
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise forms.ValidationError('User with this ID does not exist.')

    class Meta:
        model = Evidence
        fields = ['evidence_description', 'evidence_status', 'evidence_type', 'case', 'evidence_number',
                  'evidence_acquired_by', 'evidence_acquired_date', 'evidence_chain_of_custody']


class ChainOfCustodyForm(forms.Form):
    date = forms.DateField(
        widget=forms.DateInput(
            attrs={
                "class": "form-control datepicker",
                "id": "coc_date"
            }
        )
    )
    user = forms.ModelChoiceField(
        queryset=User.objects.all(), to_field_name="id",
        widget=forms.Select(
            attrs={
                "class": "form-control select2",
                "id": "coc_user"}
        )
    )
    action = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "coc_action",
                "placeholder": "Created/Collected something..."
            }
        )
    )
    detail = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "coc_details",
                "placeholder": "Location: xx/something..."
            }
        )
    )

class AdditionalInfoForm(forms.Form):
    addinfo_name = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "addinfo_name",
                "placeholder": ""
            }
        )
    )
    addinfo_agency = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "addinfo_agency",
                "placeholder": ""
            }
        )
    )
    addinfo_phone = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "addinfo_phone",
                "placeholder": ""
            }
        )
    )
    addinfo_fax = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "addinfo_fax",
                "placeholder": ""
            }
        )
    )
    addinfo_address = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "addinfo_address",
                "placeholder": ""
            }
        )
    )
    addinfo_email = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "addinfo_email",
                "placeholder": ""
            }
        )
    )
    addinfo_notes = forms.CharField(
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "id": "addinfo_notes",
                "placeholder": ""
            }
        )
    )