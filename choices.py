AREA_ACCESS = (
    ('PTB', 'PTB'),
    ('APRON', 'APRON'),
    ('CARGO', 'CARGO'),
    ('VIP', 'VIP'),
)


PERMIT_OFFICER_ACTION = (
    ( None, 'Pending'),
    ('Approved', 'Approved'),   
    ('Rejected', 'Rejected'),
)

SECURITY_MANAGER_ACTION = (
    ( None, 'Pending'),
    ('Approved', 'Approved'),
    ('Rejected', 'Rejected'),
)

DEPARTMENT_MANAGER_ACTION = (
    ( None, 'Pending'),
    ('Approved', 'Approved'),
    ('Rejected', 'Rejected'),      
 )

AVIATION_MANAGER_ACTION = (
    ( None, 'Pending'),
    ('Approved', 'Approved'),
    ('Rejected', 'Rejected'),   
)

VETTING_COMMITEE_ACTION = (
    ( None, 'Pending'),
    ('Approved', 'Approved'),
    ('Rejected', 'Rejected'),   
)

NATIONALITY_CHOICES = (
    ( None, 'Choose your nationality'),
    ('Ugandan', 'Ugandan'),
    ('Non-Ugandan', 'Non-Uganda'),   
)

LEGAL_STATUS_CHOICES = (
    ( None, 'Choose your legal status'),
    ('Registered', 'Registered'),
    ('Nonregistered', 'Nonregistered')
)