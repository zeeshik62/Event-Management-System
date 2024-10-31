export const calculateTicketsAndAddTicketId = (event, includeBookedUsers = false) => {
    // Calculate total tickets sold for each category
    const totalTicketsSold = {
      vip: event.ticketsSold.vip,
      general: event.ticketsSold.general,
    };
  
    // Create a new object for the event, including total tickets sold
    const eventWithTotalTicketsSold = {
      ...event.toObject(), // Convert Mongoose document to plain JavaScript object
      totalTicketsSold,    // Add the total tickets sold
    };
  
    // Include booked users if specified
    if (includeBookedUsers) {
      eventWithTotalTicketsSold.bookedUsers = event.bookedUsers; // Include booked users
    }
  
    return eventWithTotalTicketsSold; // Return the modified event object
  };