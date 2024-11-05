import React from 'react';
import {
  MDBBtn,
  MDBContainer,
  MDBRow,
  MDBCol,
  MDBCard,
  MDBCardBody,
  MDBInput,
  MDBCheckbox,
  MDBIcon
} from 'mdb-react-ui-kit';
import { useFormik } from 'formik';
import * as Yup from 'yup';

function Signup() {
  const formik = useFormik({
    initialValues: {
      fullName: '',
      email: '',
      password: '',
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
    }),
    onSubmit: (values) => {
      console.log(values);
      // You can reset the form or handle the form submission
      // formik.resetForm();
    },
  });

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
              <MDBRow>
                <div className="text-center">
                  <img src="https://mdbcdn.b-cdn.net/img/Photos/new-templates/bootstrap-login-form/lotus.webp"
                    style={{ width: '185px' }} alt="logo" />
                </div>

                <MDBCol col='12'>
                  <MDBInput
                    wrapperClass='mt-1'
                    label='Full name'
                    id='fullName' // Use an ID that corresponds to your formik field
                    type='text'
                    value={formik.values.fullName} // Bind the value to formik
                    onChange={formik.handleChange} // Correctly handle changes
                    onBlur={formik.handleBlur} // Handle blur event
                    invalid={formik.touched.fullName && Boolean(formik.errors.fullName)} // Show error if applicable
                  />
                  {formik.touched.fullName && formik.errors.fullName ? (
                    <div className="text-danger">{formik.errors.fullName}</div>
                  ) : null}
                </MDBCol>
              </MDBRow>

              <MDBInput
                wrapperClass='mt-4'
                label='Email'
                id='email' // Use an ID that corresponds to your formik field
                type='email'
                value={formik.values.email}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                invalid={formik.touched.email && Boolean(formik.errors.email)}
              />
              {formik.touched.email && formik.errors.email ? (
                <div className="text-danger">{formik.errors.email}</div>
              ) : null}

              <MDBInput
                wrapperClass='mt-4'
                label='Password'
                id='password' // Use an ID that corresponds to your formik field
                type='password'
                value={formik.values.password}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                invalid={formik.touched.password && Boolean(formik.errors.password)}
              />
              {formik.touched.password && formik.errors.password ? (
                <div className="text-danger">{formik.errors.password}</div>
              ) : null}
              

              {/* <div className='d-flex justify-content-center my-4'>
                <MDBCheckbox
                  name='subscribe'
                  checked={formik.values.subscribe}
                  onChange={formik.handleChange}
                  id='flexCheckDefault'
                  label='Subscribe to our newsletter'
                />
              </div> */}

              <MDBBtn
                className="mb-4 my-5 w-100 gradient-custom-2"
                onClick={formik.handleSubmit} // Use handleSubmit for form submission
              >
                Sign up
              </MDBBtn>

              <div className="text-center">
                <p>OR LOGIN WITH:</p>
                <MDBBtn tag='a' color='orange' className='mx-2 with-google'>
                  <MDBIcon fab icon='google' size="sm" />
                </MDBBtn>
                <MDBBtn tag='a' color='orange' className='mx-2 with-google'>Login</MDBBtn>
              </div>
            </MDBCardBody>
          </MDBCard>
        </MDBCol>
      </MDBRow>
    </MDBContainer>
  );
}

export default Signup;