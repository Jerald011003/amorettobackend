from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from base.models import HeartList, User, Profile
from django.http import Http404, HttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import get_object_or_404
from base.serializers import ReviewSerializer, HeartListSerializer

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Q

@api_view(['POST'])
def addHeartUser(request):
    user = request.user
    user_receiver_email = request.data['userReceiver']
    user_receiver = User.objects.get(email=user_receiver_email)
    is_heart = request.data['isHeart']
    can_message = request.data['canMessage']
    heartlist = HeartList.objects.create(user=user, userReceiver=user_receiver, isHeart=is_heart, canMessage=can_message, userHeart=user_receiver, userOwner=user)
    serializer = HeartListSerializer(heartlist, many=False)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getHeartList(request):
    user = request.user
    heartlist = HeartList.objects.filter(Q(user=user) | Q(userReceiver=user))
    serializer = HeartListSerializer(heartlist, many=True)
    return Response(serializer.data)


@api_view(['GET'])
# @permission_classes([IsAuthenticated])
def getAllHeartList(request):
    heartlist = HeartList.objects.all()
    serializer = HeartListSerializer(heartlist, many=True)
    return Response(serializer.data)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_hearts(request, pk):
    user = request.data
    data = request.data
    heartlist = HeartList.objects.get(_id=pk)

    # Check if the authenticated user is the receiver of the heartlist item
    if request.user != heartlist.userReceiver:
        return Response({'error': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
    
    heartlist.isHeart = data['isHeart']
    heartlist.canMessage = data['canMessage']
 

    heartlist.save()

    serializer = HeartListSerializer(heartlist, many=False)
    return Response(serializer.data)


@api_view(['DELETE'])
# @permission_classes([IsAuthenticated])
def delete_hearts(request, pk):
    heartlist = get_object_or_404(HeartList, _id=pk)

    # Check if the authenticated user is the owner of the profile
    # if request.user != heartlist.user:
    #     return Response({'error': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

    heartlist.delete()
    return Response('Heart deleted')
