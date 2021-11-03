/* eslint-disable */
import axios from 'axios';
import { showAlert } from './alerts';
const stripe = Stripe(
  'pk_test_51HveKPG1G7oWqZh88mrl8znv9XdH6CaaEJXH6lvFFaM98RMhWjsPhNjoPPb8VO1oVBPskbMrEkKFhR8j2s5tH9Ys00Fbur5cdj'
);

export const bookTour = async tourId => {
  try {
    // 1) Get checkout session from API
    const session = await axios(
      `/api/v1/bookings/checkout-session/${tourId}`
    );

    // 2) Create checkout form + chanre credit card
    await stripe.redirectToCheckout({
      sessionId: session.data.session.id
    });
  } catch (err) {
    showAlert('error', err);
  }
};
