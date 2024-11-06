import React from 'react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  MDBBtn,
  MDBContainer,
  MDBRow,
  MDBCol,
  MDBCard,
  MDBCardBody,
  MDBInput,
  MDBDropdown, // Import MDBDropdown and related components
  MDBDropdownToggle,
  MDBDropdownMenu,
  MDBDropdownItem,
  MDBIcon
} from 'mdb-react-ui-kit';
import { useFormik } from 'formik';
import * as Yup from 'yup';

function Signup() {

  const navigate = useNavigate();
  const handleLoginClick = () => {
    navigate('/login'); 
  };
  
const [roles,setRoles] = useState([]);
const [selectedRole, setSelectedRole] = useState('');
const [selectedRoleId, setSelectedRoleId] = useState('');

  const formik = useFormik({
    initialValues: {
      fullName: '',
      email: '',
      password: '',
      role: '', // New field for dropdown
      subscribe: false,
    },
    validationSchema: Yup.object({
      fullName: Yup.string().required('Full name is required'),
      email: Yup.string()
        .email('Invalid email format')
        .required('Email is required'),
      password: Yup.string()
        .min(6, 'Password must be at least 6 characters long')
        .required('Password is required'),
      role: Yup.string().required('Role is required'),
    }),
    onSubmit:async (values) => {
     const payload = {
      fullname: values.fullName,
      email: values.email,
      password: values.password,
      roleId: selectedRoleId, 
     };
     try {
      const response = await fetch ('http://localhost:5000/api/register',{
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json();

      if(response.ok){
        navigate('/login')
      }else{
        console.log('registration failed:')
      }
     }catch(error){
      console.log('Error during registration:', error)
     }
    },
  });

  useEffect(()=>{
    const fetchRoles = async () => {
      try{
        const response = await fetch('http://localhost:5000/api/get-role');
        const data = await response.json();
        setRoles(data);   
      }
      catch(error){
        console.log('Error fetching roles:', error)
      }
    }

    fetchRoles();
  }, [])
  const handleRoleSelect = (role) => {
    setSelectedRole(role.name); // Set the role name
    setSelectedRoleId(role._id); // Store the role ID
    formik.setFieldValue('role', role.name); // Update formik field value
  };

  return (
    <MDBContainer fluid className='p-4 background-radial-gradient overflow-hidden signup-height'>
      <MDBRow>
        <MDBCol md='6' className='text-center text-md-start d-flex flex-column justify-content-center'>
          <h1 className="my-5 display-3 fw-bold ls-tight px-3 TBO-color">
            The best offer <br />
            <span className='left-text-heading-signup'>for your business</span>
          </h1>
          <p className='px-3 left-text-signup'>
            Lorem ipsum dolor sit amet consectetur adipisicing elit.
            Eveniet, itaque accusantium odio, soluta, corrupti aliquam
            quibusdam tempora at cupiditate quis eum maiores libero
            veritatis? Dicta facilis sint aliquid ipsum atque?
          </p>
        </MDBCol>

        <MDBCol md='6' className='position-relative'>
          <div id="radius-shape-1" className="position-absolute rounded-circle shadow-5-strong"></div>
          <div id="radius-shape-2" className="position-absolute shadow-5-strong"></div>

          <MDBCard className='my-5 bg-glass'>
            <MDBCardBody className='p-5'>
              <div className="text-center">
                <img src="https://mdbcdn.b-cdn.net/img/Photos/new-templates/bootstrap-login-form/lotus.webp"
                  style={{ width: '185px' }} alt="logo" />
              </div>

              <MDBCol col='12'>
                <MDBInput
                  wrapperClass='mt-1'
                  label='Full name'
                  id='fullName'
                  type='text'
                  value={formik.values.fullName} 
                  onChange={formik.handleChange} 
                  onBlur={formik.handleBlur}
                  invalid={formik.touched.fullName && Boolean(formik.errors.fullName)? 'true' : undefined}
                />
                {formik.touched.fullName && formik.errors.fullName ? (
                  <div className="text-danger">{formik.errors.fullName}</div>
                ) : null}
              </MDBCol>

              <MDBInput
                wrapperClass='mt-4'
                label='Email'
                id='email' 
                type='email'
                value={formik.values.email}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                invalid={formik.touched.email && Boolean(formik.errors.email)? 'true' : undefined}
              />
              {formik.touched.email && formik.errors.email ? (
                <div className="text-danger">{formik.errors.email}</div>
              ) : null}

              <MDBInput
                wrapperClass='mt-4'
                label='Password'
                id='password' 
                type='password'
                value={formik.values.password}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                invalid={formik.touched.password && Boolean(formik.errors.password)? 'true' : undefined}
              />
              {formik.touched.password && formik.errors.password ? (
                <div className="text-danger">{formik.errors.password}</div>
              ) : null}

             <MDBDropdown group className='mt-2'>
                  <MDBDropdownToggle color='danger'>{selectedRole || 'Select Role'}</MDBDropdownToggle>
                  <MDBDropdownMenu>
                    {roles.length > 0 ? (
                      roles.map((role, index) => (
                        <MDBDropdownItem link key={index} onClick={() => {
                          setSelectedRole(role.name);
                          formik.setFieldValue('role', role.name);
                        }}>
                          {role.name}
                        </MDBDropdownItem>
                      ))
                    ) : (
                      <MDBDropdownItem disabled link>No roles available</MDBDropdownItem>
                    )}
                  </MDBDropdownMenu>
           </MDBDropdown>
           {formik.touched.role && formik.errors.role ? (
            <div className="text-danger">{formik.errors.role}</div>
          ) : null}

              <MDBBtn
                className="mb-4 my-5 w-100 gradient-custom-2" type='submit'
                onClick={formik.handleSubmit} 
              >Sign up</MDBBtn>

              <div className="text-center">
                <p>OR LOGIN WITH:</p>
                <MDBBtn tag='a' color='orange' className='mx-2 with-google'>
                  <MDBIcon fab icon='google' size="sm" />
                </MDBBtn>
                <MDBBtn tag='a' color='orange' className='mx-2 with-google'
                  onClick={handleLoginClick}
                >Login</MDBBtn>
              </div>
            </MDBCardBody>
          </MDBCard>
        </MDBCol>
      </MDBRow>
    </MDBContainer>
  );
}

export default Signup;
